# This file is part of PywerView.

# PywerView is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# PywerView is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with PywerView.  If not, see <http://www.gnu.org/licenses/>.

# Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2023

import random
import multiprocessing
import select

import pywerview.objects.rpcobjects as rpcobj
from pywerview.functions.net import NetRequester
from pywerview.functions.misc import Misc
from pywerview.worker.hunting import UserHunterWorker, ProcessHunterWorker, EventHunterWorker

class Hunter(NetRequester):
    def __init__(self, target_computer, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False, do_tls=False,
                 domain_controller=str(), queried_domain=str()):
        NetRequester.__init__(self, target_computer, domain, user, password,
                              lmhash, nthash, do_kerberos, do_tls, domain_controller)
        self._target_domains = list()
        self._target_computers = list()
        self._target_users = list()
        self._parent_pipes = list()
        self._workers = list()

    def _build_target_domains(self, queried_domain=str()):
        # TODO: implement forest search
        if not queried_domain:
            queried_domain = self._domain
        self._queried_domain = queried_domain
        self._target_domains = [self._queried_domain]

    def _build_target_computers(self, queried_computername=list(), queried_computerfile=None,
                                queried_computerfilter=str(), queried_computeradspath=str(),
                                unconstrained=False, stealth=False,
                                stealth_source=['dfs', 'dc', 'file']):
        if queried_computername:
            self._target_computers = queried_computername

        if not self._target_computers:
            if queried_computerfile:
                self._logger.debug('Computer file provided: {}'.format(queried_computerfile.name))
                with queried_computerfile as _:
                    self._target_computers = [x.rstrip('\n') for x in queried_computerfile.readlines()]

            elif stealth:
                self._logger.debug('Stealth mode enabled')
                for target_domain in self._target_domains:
                    for source in stealth_source:
                        if source == 'dfs':
                            self._target_computers += [x.remoteservername \
                                    for x in self.get_dfsshare(queried_domain=target_domain)]
                        elif source == 'dc':
                            self._target_computers += [x.dnshostname \
                                    for x in self.get_netdomaincontroller(queried_domain=target_domain)]
                        elif source == 'file':
                            self._target_computers += [x.dnshostname \
                                    for x in self.get_netfileserver(queried_domain=target_domain)]
            else:
                self._logger.debug('Computer list not provided by the user, we retrieve it with get-netcomputer')
                for target_domain in self._target_domains:
                    self._target_computers = [x.dnshostname for x in self.get_netcomputer(
                        queried_domain=target_domain, unconstrained=unconstrained,
                        ads_path=queried_computeradspath, custom_filter=queried_computerfilter)]

        # Hack to remove empty arrays from the list
        self._target_computers = [x for x in self._target_computers if x]

        # TODO: automatically convert server names to IP address (DNS, LLMNR, NBT-NS, etc.)
        self._target_computers = list(set(self._target_computers))
        random.shuffle(self._target_computers)

        self._logger.debug('{} computers in the target list'.format(len(self._target_computers)))
        self._logger.log(self._logger.ULTRA,'Target computers: {}'.format(self._target_computers))

        if not self._target_computer:
            raise ValueError('No computers to search against')

    def _build_target_users(self, queried_groupname=str(), target_server=str(),
                            queried_username=str(), queried_userfilter=str(),
                            queried_useradspath=str(), queried_userfile=None,
                            admin_count=False, allow_delegation=False,
                            show_all=False, foreign_users=False):
        if show_all or foreign_users:
            attributes = {'memberdomain': str(), 'membername': str()}
            self._target_users.append(rpcobj.TargetUser(attributes))
        elif target_server:
            self._logger.debug('Target server: {}, we hunt for its localadmins'.format(target_server))
            with NetRequester(target_server, domain, user, password, lmhash,
                              nthash, do_kerberos, do_tls, domain_controller) as target_server_requester:
                for x in target_server_requester.get_netlocalgroup(recurse=True):
                    if x.isdomain and not x.isgroup:
                        attributes = {'memberdomain': x.name.split('/')[0].lower(),
                                      'membername': x.name.split('/')[1].lower()}

                        self._target_users.append(rpcobj.TargetUser(attributes))
        elif queried_userfile:
            self._logger.debug('User file provided: {}'.format(queried_userfile.name))
            with queried_userfile as _:
                for x in queried_userfile.readlines():
                    attributes = dict()
                    attributes['membername'] = x.rstrip('\n')
                    attributes['memberdomain'] = self._target_domains[0]

                    self._target_users.append(rpcobj.TargetUser(attributes))
        elif queried_username:
            self._logger.debug('Queried user: {}'.format(queried_username))
            attributes = dict()
            attributes['membername'] = queried_username.lower()
            attributes['memberdomain'] = self._target_domains[0]

            self._target_users.append(rpcobj.TargetUser(attributes))
        elif queried_useradspath or queried_userfilter or admin_count or allow_delegation:
            self._logger.debug('Custom query used, launching get-netuser')
            for target_domain in self._target_domains:
                for x in self.get_netuser(ads_path=queried_useradspath,
                                          custom_filter=queried_userfilter,
                                          admin_count=admin_count,
                                          allow_delegation=allow_delegation,
                                          queried_domain=target_domain):
                            attributes = dict()
                            attributes['memberdomain'] = target_domain
                            attributes['membername'] = x.samaccountname

                            self._target_users.append(rpcobj.TargetUser(attributes))
        else:
            for target_domain in self._target_domains:
                self._target_users += self.get_netgroupmember(queried_domain=target_domain,
                                                              queried_groupname=queried_groupname,
                                                              recurse=True)

        # Hack to remove empty arrays from the list
        self._target_users = [x for x in self._target_users if x]
        self._target_users = list(set(self._target_users))

        self._logger.debug('{} users in the target list'.format(len(self._target_users)))
        self._logger.log(self._logger.ULTRA,'Target users: {}'.format(self._target_users))

        if (not show_all) and (not foreign_users) and (not self._target_users):
            raise ValueError('No users to search for')

    def _build_workers(self, threads, worker_class, worker_args):
        for i in range(threads):
            parent_pipe, worker_pipe = multiprocessing.Pipe()
            self._parent_pipes.append(parent_pipe)
            worker = worker_class(worker_pipe, self._domain, self._user,
                                            self._password, self._lmhash, self._nthash,
                                            self._do_kerberos, self._do_tls, *worker_args)

            worker.start()
            self._workers.append(worker)

    def _process_workers(self):
        jobs_done, total_jobs = 0, len(self._target_computers)
        try:
            while jobs_done < total_jobs:
                if self._target_computers:
                    write_watch_list = self._parent_pipes
                else:
                    write_watch_list = list()
                rlist, wlist, _ = select.select(self._parent_pipes, write_watch_list, list())

                for readable in rlist:
                    jobs_done += 1
                    results = readable.recv()
                    for result in results:
                        yield result
                for writable in wlist:
                    try:
                        target_computer = self._target_computers.pop(0)
                        writable.send(target_computer)
                    except IndexError:
                        pass
        except KeyboardInterrupt:
            pass
        finally:
            for worker in self._workers:
                worker.terminate()

class UserHunter(Hunter):
    def invoke_userhunter(self, queried_computername=list(), queried_computerfile=None,
            queried_computerfilter=str(), queried_computeradspath=str(),
            unconstrained=False, queried_groupname=str(), target_server=str(),
            queried_username=str(), queried_userfilter=str(), queried_useradspath=str(),
            queried_userfile=None, threads=1, admin_count=False, allow_delegation=False,
            stop_on_success=False, check_access=False, queried_domain=str(), stealth=False,
            stealth_source=['dfs', 'dc', 'file'], show_all=False, foreign_users=False):

        self._logger.debug('Building target domain')

        self._build_target_domains(queried_domain)

        self._logger.debug('Building target computers')

        self._build_target_computers(queried_computername=queried_computername,
                                     queried_computerfile=queried_computerfile,
                                     queried_computerfilter=queried_computerfilter,
                                     queried_computeradspath=queried_computeradspath,
                                     unconstrained=unconstrained, stealth=stealth,
                                     stealth_source=stealth_source)

        self._logger.debug('Building target users')

        self._build_target_users(queried_groupname=queried_groupname,
                                 target_server=target_server,
                                 queried_username=queried_username,
                                 queried_userfilter=queried_userfilter,
                                 queried_useradspath=queried_useradspath,
                                 queried_userfile=queried_userfile,
                                 admin_count=admin_count, allow_delegation=allow_delegation,
                                 show_all=show_all, foreign_users=foreign_users)

        if foreign_users:
            with Misc(self._domain_controller, self._domain, self._user,
                      self._password, self._lmhash, self._nthash, self._do_kerberos, self._do_tls) as misc_requester:
                domain_sid = misc_requester.get_domainsid(queried_domain)
                domain_short_name = misc_requester.convert_sidtont4(domain_sid).split('\\')[0]
        else:
            domain_short_name = None

        self._logger.debug('Launching workers ({} threads)...'.format(threads))

        self._build_workers(threads, UserHunterWorker, (foreign_users, stealth,
                                                        self._target_users,
                                                        domain_short_name, check_access))
        return self._process_workers()

class ProcessHunter(Hunter):
    def invoke_processhunter(self, queried_computername=list(), queried_computerfile=None,
            queried_computerfilter=str(), queried_computeradspath=str(),
            queried_processname=list(), queried_groupname=str(), target_server=str(),
            queried_username=str(), queried_userfilter=str(), queried_useradspath=str(),
            queried_userfile=None, threads=1, stop_on_success=False, queried_domain=str(),
            show_all=False):

        self._logger.debug('Building target domain')

        self._build_target_domains(queried_domain)

        self._logger.debug('Building target computers')

        self._build_target_computers(queried_computername=queried_computername,
                                     queried_computerfile=queried_computerfile,
                                     queried_computerfilter=queried_computerfilter,
                                     queried_computeradspath=queried_computeradspath)

        self._logger.debug('Building target users')

        self._build_target_users(queried_groupname=queried_groupname,
                                 target_server=target_server,
                                 queried_username=queried_username,
                                 queried_userfilter=queried_userfilter,
                                 queried_useradspath=queried_useradspath,
                                 queried_userfile=queried_userfile,
                                 show_all=show_all)

        self._logger.debug('Launching workers ({} threads)...'.format(threads))

        self._build_workers(threads, ProcessHunterWorker, (queried_processname,
                                                           self._target_users))

        return self._process_workers()

class EventHunter(Hunter):
    def invoke_eventhunter(self, queried_computername=list(), queried_computerfile=None,
                           queried_computerfilter=str(), queried_computeradspath=str(),
                           queried_groupname=str(), target_server=str(), queried_username=str(),
                           queried_useradspath=str(), queried_userfilter=str(),
                           queried_userfile=None, threads=1, queried_domain=str(),
                           search_days=3):

        self._logger.debug('Building target domain')

        self._build_target_domains(queried_domain)

        self._logger.debug('Building target computers')

        self._build_target_computers(queried_computername=queried_computername,
                                     queried_computerfile=queried_computerfile,
                                     queried_computerfilter=queried_computerfilter,
                                     queried_computeradspath=queried_computeradspath)

        self._logger.debug('Building target users')

        self._build_target_users(queried_groupname=queried_groupname,
                                 target_server=target_server,
                                 queried_username=queried_username,
                                 queried_userfilter=queried_userfilter,
                                 queried_useradspath=queried_useradspath,
                                 queried_userfile=queried_userfile)

        self._logger.debug('Launching workers ({} threads)...'.format(threads))

        self._build_workers(threads, EventHunterWorker, (search_days,
                                                         self._target_users))

        return self._process_workers()
