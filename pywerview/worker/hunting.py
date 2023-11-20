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

import logging
from multiprocessing import Process, Pipe

from pywerview.functions.net import NetRequester
from pywerview.functions.misc import Misc
import pywerview.objects.rpcobjects as rpcobj

class HunterWorker(Process):
    def __init__(self, pipe, domain, user, password, lmhash, nthash, do_kerberos, do_tls):
        Process.__init__(self)
        self._pipe = pipe
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._do_tls = do_tls

        logger = logging.getLogger('pywerview_main_logger.HunterWorker')
        logger.ULTRA = 5
        self._logger = logger

    def terminate(self):
        self._pipe.close()
        Process.terminate(self)

    def run(self):
        while True:
            target_computer = self._pipe.recv()
            result = self._hunt(target_computer)
            self._pipe.send(result)

class UserHunterWorker(HunterWorker):
    def __init__(self, pipe, domain, user, password, lmhash, nthash, do_kerberos, do_tls,
            foreign_users, stealth, target_users, domain_short_name, check_access):
        HunterWorker.__init__(self, pipe, domain, user, password, lmhash,
                nthash, do_kerberos, do_tls)
        self._foreign_users = foreign_users
        self._stealth = stealth
        self._target_users = target_users
        self._domain_short_name = domain_short_name
        self._check_access = check_access

    # TODO: test foreign user hunting
    def _hunt(self, target_computer):
        # TODO: implement ping of target
        results = list()
        # First, we get every distant session on the target computer
        distant_sessions = list()
        self._logger.debug('Start hunting on {}'.format(target_computer))
        with NetRequester(target_computer, self._domain, self._user, self._password,
                          self._lmhash, self._nthash, self._do_kerberos, self._do_tls) as net_requester:
            if not self._foreign_users:
                self._logger.log(self._logger.ULTRA, 'Calling get_netsession on {}'.format(target_computer))
                distant_sessions += net_requester.get_netsession()
            if not self._stealth:
                self._logger.log(self._logger.ULTRA, 'Calling get_netloggedon on {}'.format(target_computer))
                distant_sessions += net_requester.get_netloggedon()

        self._logger.debug('{} distant sessions found'.format(len(distant_sessions)))
        self._logger.log(self._logger.ULTRA,'Distant sessions: {}'.format(distant_sessions))

        # For every session, we get information on the remote user
        for session in distant_sessions:
            try:
                username = session.sesi10_username
                userdomain = str()
                session_from = session.sesi10_cname
                if session_from.startswith('\\'):
                    session_from = session_from.lstrip('\\')
            except AttributeError:
                self._logger.warning('Error extracting username/session from the session')
                username = session.wkui1_username
                userdomain = session.wkui1_logon_domain
                session_from = str()

            # If we found a user
            if username:
                self._logger.debug('User found in session')
                # We see if it's in our target user group
                for target_user in self._target_users:
                    if target_user.membername.lower() in username.lower():

                        self._logger.debug('We found our target! ({})'.format(username))

                        # If we fall in this branch, we're looking for foreign users
                        # and found a user in the same domain
                        if self._domain_short_name and self._domain_short_name.lower() == userdomain.lower():
                            continue

                        attributes = dict()
                        if userdomain:
                            attributes['userdomain'] = userdomain
                        else:
                            attributes['userdomain'] = target_user.memberdomain
                        attributes['username'] = username
                        attributes['computername'] = target_computer
                        attributes['sessionfrom'] = session_from

                        if self._check_access:
                            self._logger.debug('"Check access" requested, calling invoke-checklocaladminaccess')
                            with Misc(target_computer, self._domain, self._user, self._password,
                                              self._lmhash, self._nthash, self._do_kerberos) as misc_requester:
                                attributes['localadmin'] = misc_requester.invoke_checklocaladminaccess()
                        else:
                            attributes['localadmin'] = str()

                        results.append(rpcobj.RPCObject(attributes))

        return results

class ProcessHunterWorker(HunterWorker):
    def __init__(self, pipe, domain, user, password, lmhash, nthash, do_kerberos, do_tls,
            process_name, target_users):
        HunterWorker.__init__(self, pipe, domain, user, password, lmhash, nthash, do_kerberos, do_tls)
        self._process_name = process_name
        self._target_users = target_users

    def _hunt(self, target_computer):
        results = list()

        distant_processes = list()
        with NetRequester(target_computer, self._domain, self._user, self._password,
                          self._lmhash, self._nthash, self._do_kerberos, self._do_tls) as net_requester:
            distant_processes = net_requester.get_netprocess()

        for process in distant_processes:
            if self._process_name:
                for process_name in self._process_name:
                    if process_name.lower() in process.processname.lower():
                        results.append(process)
            elif self._target_users:
                for target_user in self._target_users:
                    if target_user.membername.lower() in process.user.lower():
                        results.append(process)

        return results

class EventHunterWorker(HunterWorker):
    def __init__(self, pipe, domain, user, password, lmhash, nthash, do_kerberos, do_tls,
            search_days, target_users):
        HunterWorker.__init__(self, pipe, domain, user, password, lmhash, nthash, do_kerberos, do_tls)
        self._target_users = target_users
        self._search_days = search_days

    def _hunt(self, target_computer):
        results = list()

        distant_processes = list()
        with NetRequester(target_computer, self._domain, self._user, self._password,
                          self._lmhash, self._nthash, self._do_kerberos, self._do_tls) as net_requester:
            distant_events = net_requester.get_userevent(date_start=self._search_days)

        for event in distant_events:
            if self._target_users:
                for target_user in self._target_users:
                    if target_user.membername.lower() in event.username.lower():
                        results.append(event)

        return results

