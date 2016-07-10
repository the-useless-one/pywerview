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

import random

from pywerview.net import get_netdomaincontroller, get_dfsshare, get_netfileserver, \
        get_netcomputer, get_netlocalgroup, get_netuser, get_netgroupmember, \
        get_netsession, get_netloggedon
from pywerview.misc import invoke_checklocaladminaccess
import pywerview.rpcobjects as rpcobj

def invoke_userhunter(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_computername=list(),
        queried_computerfile=None, queried_computeradspath=str(),
        unconstrained=False, queried_groupname=str(), target_server=str(),
        queried_username=str(), queried_useradspath=str(), queried_userfile=None,
        admin_count=False, allow_delegation=False, stop_on_success=False,
        check_access=True, queried_domain=str(), stealth=False,
        stealth_source=['dfs', 'dc', 'file'], show_all=False):

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
            source_to_function = {'dfs': get_dfsshare, 'dc': get_netdomaincontroller,
                    'file': get_netfileserver}
            for target_domain in target_domains:
                for source in stealth_source:
                    if source == 'dfs':
                        queried_computername += [x.remoteservername for x in get_dfsshare(domain_controller,
                                domain, user, password, lmhash, nthash, queried_domain=target_domain)]
                    elif source == 'dc':
                        queried_computername += get_netdomaincontroller(domain_controller,
                                domain, user, password, lmhash, nthash, queried_domain=target_domain)
                    elif source == 'file':
                        queried_computername += [x.dnshostname for x in get_netfileserver(domain_controller,
                                domain, user, password, lmhash, nthash, queried_domain=target_domain)]
        else:
            for target_domain in target_domains:
                queried_computername = [x.dnshostname for x in get_netcomputer(domain_controller,
                        domain, user, password, lmhash, nthash, queried_domain=target_domain,
                        unconstrained=unconstrained, ads_path=queried_computeradspath)]

    # TODO: automatically convert server names to IP address (DNS, LLMNR, NBT-NS, etc.)
    queried_computername = list(set(queried_computername))
    random.shuffle(queried_computername)

    # Now, we build the target users
    target_users = list()
    if show_all:
        attributes = {'memberdomain': str(), 'membername': str()}
        target_users.append(rpcobj.TargetUser(attributes))
    elif target_server:
        for x in get_netlocalgroup(target_server, domain_controller, domain,
                user, password, lmhash, nthash, recurse=True):
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
            for x in get_netuser(domain_controller, domain, user, password,
                    lmhash, nthash, ads_path=queried_useradspath,
                    admin_count=admin_count, allow_delegation=allow_delegation,
                    queried_domain=target_domain):
                        attributes = dict()
                        attributes['memberdomain'] = target_domain
                        attributes['membername'] = x.samaccountname

                        target_users.append(rpcobj.TargetUser(attributes))
    else:
        for target_domain in target_domains:
            target_users += get_netgroupmember(domain_controller, domain, user, password, lmhash,
                    nthash, queried_domain=target_domain, queried_groupname=queried_groupname)

    target_users = list(set(target_users))

    if (not show_all) and (not target_users):
        raise ValueError('No users to search for')

    results = list()
    # TODO: implement multiprocessing on user hunting
    # TODO: implement search for foreign users
    for target_computer in queried_computername:
        distant_sessions = get_netsession(target_computer, domain, user, password,
                lmhash, nthash)
        if not stealth:
            distant_sessions += get_netloggedon(target_computer, domain, user,
                    password, lmhash, nthash)

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
            if username:
                for target_user in target_users:
                    if target_user.membername.lower() in username.lower():
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

    return results

