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

from multiprocessing import Process, Pipe

from pywerview.functions.net import NetRequester
import pywerview.objects.rpcobjects as rpcobj

class UserHunterWorker(Process):
    def __init__(self, domain, user, password, lmhash, nthash, foreign_users, verbose,
                 stealth, target_users, domain_short_name, check_access):
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._foreign_users = foreign_users
        self._verbose = verbose
        self._stealth = stealth
        self._target_users = target_users
        self._domain_short_name = domain_short_name
        self._check_access = check_access
        Process.__init__(self)

    def run(self):
        pass

    # TODO: test foreign user hunting
    def _enumerate_sessions(foreign_users, domain, user, password, lmhash, nthash,
            verbose, stealth, target_users, domain_short_name, check_access, target_computer):
        # TODO: implement ping of target
        results = list()
        # First, we get every distant session on the target computer
        distant_sessions = list()
        if not foreign_users:
            distant_sessions += get_netsession(target_computer, domain, user, password,
                    lmhash, nthash)
        if not stealth:
            distant_sessions += get_netloggedon(target_computer, domain, user, password,
                    lmhash, nthash)

        # For every session, we get information on the remote user
        for session in distant_sessions:
            try:
                username = session.sesi10_username
                userdomain = str()
                session_from = session.sesi10_cname
                if session_from.startswith('\\'):
                    session_from = session_from.lstrip('\\')
            except AttributeError:
                username = session.wkui1_username
                userdomain = session.wkui1_logon_domain
                session_from = str()

            # If we found a user
            if username:
                # We see if it's in our target user group
                for target_user in target_users:
                    if target_user.membername.lower() in username.lower():

                        # If we fall in this branch, we're looking for foreign users
                        # and found a user in the same domain
                        if domain_short_name and domain_short_name.lower() == userdomain.lower():
                            continue

                        attributes = dict()
                        if userdomain:
                            attributes['userdomain'] = userdomain
                        else:
                            attributes['userdomain'] = target_user.memberdomain
                        attributes['username'] = username
                        attributes['computername'] = target_computer
                        attributes['sessionfrom'] = session_from

                        if check_access:
                            attributes['localadmin'] = invoke_checklocaladminaccess(target_computer,
                                    domain, user, password, lmhash, nthash)
                        else:
                            attributes['localadmin'] = str()

                        results.append(rpcobj.RPCObject(attributes))
                        # TODO: implement generator instead of verbose mode?
                        if verbose:
                            print results[-1], '\n'

        return results

