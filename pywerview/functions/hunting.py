# -*- coding: utf8 -*-

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

# Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2016

import functools
import random
import multiprocessing
import signal

import pywerview.objects.rpcobjects as rpcobj
from pywerview.functions.net import NetRequester
from pywerview.functions.misc import Misc
#from pywerview.functions.misc import convert_sidtont4, get_domainsid
#from pywerview.worker.hunting import UserHunterWorker

class UserHunter(NetRequester):
    def invoke_userhunter(self, queried_computername=list(), queried_computerfile=None,
            queried_computeradspath=str(), unconstrained=False, queried_groupname=str(),
            target_server=str(), queried_username=str(), queried_useradspath=str(),
            queried_userfile=None, threads=1, verbose=False, admin_count=False,
            allow_delegation=False, stop_on_success=False, check_access=False,
            queried_domain=str(), stealth=False, stealth_source=['dfs', 'dc', 'file'],
            show_all=False, foreign_users=False):

        # TODO: implement forest search
        if not queried_domain:
            queried_domain = domain

        target_domains = [queried_domain]

        # First, we build the target servers
        if queried_computerfile:
            with queried_computerfile as _:
                queried_computername = [x.rstrip('\n') for x in queried_computerfile.readlines()]

        if not queried_computername:
            if stealth:
                for target_domain in target_domains:
                    for source in stealth_source:
                        if source == 'dfs':
                            queried_computername += [x.remoteservername \
                                    for x in self.get_dfsshare(queried_domain=target_domain)]
                        elif source == 'dc':
                            queried_computername += [x.dnshostname \
                                    for x in self.get_netdomaincontroller(queried_domain=target_domain)]
                        elif source == 'file':
                            queried_computername += [x.dnshostname \
                                    for x in self.get_netfileserver(queried_domain=target_domain)]
            else:
                for target_domain in target_domains:
                    queried_computername = [x.dnshostname for x in self.get_netcomputer(
                        queried_domain=target_domain, unconstrained=unconstrained,
                        ads_path=queried_computeradspath)]

        # TODO: automatically convert server names to IP address (DNS, LLMNR, NBT-NS, etc.)
        queried_computername = list(set(queried_computername))
        random.shuffle(queried_computername)

        # Now, we build the target users
        target_users = list()
        domain_short_name = None
        if show_all or foreign_users:
            attributes = {'memberdomain': str(), 'membername': str()}
            target_users.append(rpcobj.TargetUser(attributes))
            if foreign_users:
                with Misc(domain_controller, domain, user, password, lmhash, nthash) as misc_requester:
                    domain_sid = misc_requester.get_domainsid()
                    domain_short_name = misc_requester.convert_sidtont4(domain_sid).split('\\')[0]
        elif target_server:
            with NetRequester(target_server, domain, user, password, lmhash,
                              nthash, domain_controller) as target_server_requester:
                for x in target_server_requester.get_netlocalgroup(recurse=True):
                    if x.isdomain and not x.isgroup:
                        attributes = {'memberdomain': x.name.split('/')[0].lower(),
                                'membername': x.name.split('/')[1].lower()}

                        target_users.append(rpcobj.TargetUser(attributes))
        elif queried_userfile:
            with queried_userfile as _:
                for x in queried_userfile.readlines():
                    attributes = dict()
                    attributes['membername'] = x.rstrip('\n')
                    attributes['memberdomain'] = target_domains[0]

                    target_users.append(rpcobj.TargetUser(attributes))
        elif queried_username:
            attributes = dict()
            attributes['membername'] = queried_username.lower()
            attributes['memberdomain'] = target_domains[0]

            target_users.append(rpcobj.TargetUser(attributes))
        elif queried_useradspath or admin_count or allow_delegation:
            for target_domain in target_domains:
                for x in self.get_netuser(ads_path=queried_useradspath,
                                          admin_count=admin_count,
                                          allow_delegation=allow_delegation,
                                          queried_domain=target_domain):
                            attributes = dict()
                            attributes['memberdomain'] = target_domain
                            attributes['membername'] = x.samaccountname

                            target_users.append(rpcobj.TargetUser(attributes))
        else:
            for target_domain in target_domains:
                target_users += self.get_netgroupmember(queried_domain=target_domain,
                                                        queried_groupname=queried_groupname)

        target_users = list(set(target_users))

        if (not show_all) and (not foreign_users) and (not target_users):
            raise ValueError('No users to search for')

        results = list()
        partial_enumerate_sessions = functools.partial(_enumerate_sessions,
                foreign_users, domain, user, password, lmhash, nthash, verbose,
                stealth, target_users, domain_short_name, check_access)
        # TODO: implement stop on success
        if threads > 1:
            def _init_worker():
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            pool = multiprocessing.Pool(threads, _init_worker)
            try:
                async_result = pool.map_async(partial_enumerate_sessions, queried_computername)
                pool.close()
                for result in async_result.get():
                    results += result
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
        else:
            for result in map(partial_enumerate_sessions, queried_computername):
                results += result

        return results

