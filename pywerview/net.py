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

from impacket.ldap import ldapasn1
from impacket.dcerpc.v5.ndr import NULL
import impacket.dcerpc.v5.samr
from bs4 import BeautifulSoup

import pywerview.adobjects as adobj
import pywerview.rpcobjects as rpcobj
from pywerview._ldap import *
from pywerview._rpc import *
from pywerview.misc import *

def get_adobject(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(), queried_sid=str(),
        queried_name=str(), queried_sam_account_name=str(), ads_path=str()):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    object_filter = build_substrings_filter('objectSid', '*')
    for attr_desc, attr_value in (('objectSid', queried_sid), ('name', queried_name),
            ('samAccountName', queried_sam_account_name)):
        if attr_value:
            if '*' in attr_value:
                object_filter = build_substrings_filter(attr_desc, attr_value)
            else:
                object_filter = build_equality_match_filter(attr_desc, attr_value)
            break

    results = list()
    for obj in domain_connection.search(searchFilter=object_filter, attributes=list()):
        if not isinstance(obj, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.ADObject(obj['attributes']))

    return results

def get_netuser(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_username=str(), queried_domain=str(),
        ads_path=str(), admin_count=False, spn=False, unconstrained=False,
        allow_delegation=False, custom_filter=None):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    user_search_filter = ldapasn1.Filter()
    user_search_filter['and'] = ldapasn1.And()

    user_filter = build_equality_match_filter('samAccountType', '805306368')
    user_search_filter['and'][0] = user_filter

    if unconstrained:
        unconstrained_filter = build_extensible_match_filter('1.2.840.113556.1.4.803', 'UserAccountControl', '524288')
        user_search_filter['and'][user_search_filter['and']._componentValuesSet] = unconstrained_filter

    if allow_delegation:
        allow_delegation_filter = build_extensible_match_filter('1.2.840.113556.1.4.803', 'UserAccountControl', '1048574')
        user_search_filter['and'][user_search_filter['and']._componentValuesSet] = allow_delegation_filter

    if admin_count:
        admin_count_filter = build_equality_match_filter('admincount', 1)
        user_search_filter['and'][user_search_filter['and']._componentValuesSet] = admin_count_filter

    if queried_username:
        if '*' in queried_username:
            user_name_filter = build_substrings_filter('samAccountName', queried_username)
        else:
            user_name_filter = build_equality_match_filter('samAccountName', queried_username)
        user_search_filter['and'][user_search_filter['and']._componentValuesSet] = user_name_filter

    elif spn:
        spn_filter = ldapasn1.Filter()
        spn_filter['present'] = ldapasn1.Present('servicePrincipalName')
        user_search_filter['and'][user_search_filter['and']._componentValuesSet] = spn_filter

    if custom_filter:
        user_search_filter['and'][user_search_filter['and']._componentValuesSet] = custom_filter

    results = list()
    for user in domain_connection.search(searchFilter=user_search_filter, attributes=list()):
        if not isinstance(user, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.User(user['attributes']))

    return results

def get_netgroup(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_groupname='*', queried_sid=str(), queried_username=str(),
        queried_domain=str(), ads_path=str(), admin_count=False,
        full_data=False, custom_filter=None):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    group_search_filter = ldapasn1.Filter()
    group_search_filter['and'] = ldapasn1.And()

    if admin_count:
        admin_count_filter = build_equality_match_filter('admincount', 1)
        group_search_filter['and'][group_search_filter['and']._componentValuesSet] = admin_count_filter

    if queried_username:
        if '*' in queried_username:
            group_name_filter = build_substrings_filter('samAccountName', queried_username)
        else:
            group_name_filter = build_equality_match_filter('samAccountName', queried_username)
        group_search_filter['and'][group_search_filter['and']._componentValuesSet] = group_name_filter
        attributes = ['memberOf']
    else:
        group_filter = build_equality_match_filter('objectCategory', 'group')
        group_search_filter['and'][group_search_filter['and']._componentValuesSet] = group_filter
        if queried_sid:
            group_sid_filter = build_equality_match_filter('objectSid', queried_sid)
            group_search_filter['and'][group_search_filter['and']._componentValuesSet] = group_sid_filter
        elif queried_groupname:
            if '*' in queried_groupname:
                group_name_filter = build_substrings_filter('name', queried_groupname)
            else:
                group_name_filter = build_equality_match_filter('name', queried_groupname)
            group_search_filter['and'][group_search_filter['and']._componentValuesSet] = group_name_filter

        if full_data:
            attributes=list()
        else:
            attributes=['samaccountname']

    if custom_filter:
        group_search_filter['and'][group_search_filter['and']._componentValuesSet] = custom_filter

    results = list()
    for group in domain_connection.search(searchFilter=group_search_filter, attributes=attributes):
        if not isinstance(group, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.Group(group['attributes']))

    return results

def get_netcomputer(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_computername='*', queried_spn=str(),
        queried_os=str(), queried_sp=str(), queried_domain=str(), ads_path=str(),
        printers=False, unconstrained=False, ping=False, full_data=False,
        custom_filter=None):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    computer_search_filter = ldapasn1.Filter()
    computer_search_filter['and'] = ldapasn1.And()

    computer_filter = build_equality_match_filter('samAccountType', '805306369')
    computer_search_filter['and'][0] = computer_filter

    if unconstrained:
        unconstrained_filter = build_extensible_match_filter('1.2.840.113556.1.4.803', 'UserAccountControl', '524288')
        computer_search_filter['and'][computer_search_filter['and']._componentValuesSet] = unconstrained_filter

    if printers:
        printers_filter = build_equality_match_filter('objectCategory', 'printQueue')
        computer_search_filter['and'][computer_search_filter['and']._componentValuesSet] = printers_filter

    for (attr_desc, attr_value) in (('servicePrincipalName', queried_spn),
            ('operatingSystem', queried_os), ('operatingsystemservicepack', queried_sp),
            ('dnsHostName', queried_computername)):
        if attr_value:
            if '*' in attr_value:
                f = build_substrings_filter(attr_desc, attr_value)
            else:
                f = build_equality_match_filter(attr_desc, attr_value)
            computer_search_filter['and'][computer_search_filter['and']._componentValuesSet] = f

    if custom_filter:
        computer_search_filter['and'][computer_search_filter['and']._componentValuesSet] = custom_filter

    if full_data:
        attributes=list()
    else:
        attributes=['dnsHostName']

    results = list()
    for computer in domain_connection.search(searchFilter=computer_search_filter, attributes=attributes):
        if not isinstance(computer, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.Computer(computer['attributes']))

    return results

def get_netdomaincontroller(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str()):

    domain_controller_filter = build_extensible_match_filter('1.2.840.113556.1.4.803',
            'userAccountControl', '8192')

    return get_netcomputer(domain_controller, domain, user, password,
            lmhash, nthash, queried_domain, full_data=True,
            custom_filter=domain_controller_filter)

def get_netfileserver(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(), target_users=list()):

    def split_path(path):
        split_path = path.split('\\')
        if len(split_path) >= 3:
            return split_path[2]

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain)

    users = get_netuser(domain_controller, domain, user, password,
            lmhash, nthash, queried_domain)

    results = list()
    for user in users:
        if target_users:
            for target_user in target_users:
                if user.samaccountname in target_user:
                    break
            else:
                continue
        if user.homedirectory:
            results.append(split_path(user.homedirectory))
        if user.scriptpath:
            results.append(split_path(user.scriptpath))
        if user.profilepath:
            results.append(split_path(user.profilepath))

    return results

def get_dfsshare(domain_controller, domain, user, password=str(), lmhash=str(),
        nthash=str(), version=['v1', 'v2'], queried_domain=str(),
        ads_path=str()):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    def _get_dfssharev1():
        dfs_search_filter = build_equality_match_filter('objectClass', 'fTDfs')

        results = list()
        for dfs in domain_connection.search(searchFilter=dfs_search_filter,
                attributes=['remoteservername', 'name']):
            if not isinstance(dfs, ldapasn1.SearchResultEntry):
                continue

            for remote_server in dfs['attributes'][1]['vals']:
                remote_server = str(remote_server)
                if '\\' in remote_server:
                    attributes = list()
                    attributes.append({'type': 'name', 'vals': dfs['attributes'][0]['vals']})
                    attributes.append({'type': 'remoteserver', 'vals': [remote_server.split('\\')[2]]})
                    results.append(adobj.DFS(attributes))

        return results

    def _get_dfssharev2():
        dfs_search_filter = build_equality_match_filter('objectClass',
                'msDFS-Linkv2')

        results = list()
        for dfs in domain_connection.search(searchFilter=dfs_search_filter,
                attributes=['msdfs-linkpathv2','msDFS-TargetListv2']):
            if not isinstance(dfs, ldapasn1.SearchResultEntry):
                continue

            attributes = list()

            share_name = dfs['attributes'][1]['vals'][0]

            xml_target_list = str(dfs['attributes'][0]['vals'][0])[2:].decode('utf-16le')
            soup_target_list = BeautifulSoup(xml_target_list, 'xml')
            for target in soup_target_list.targets.contents:
                if '\\' in target.string:
                    server_name, dfs_root = target.string.split('\\')[2:4]
                    attributes.append({'type': 'remoteservername',
                        'vals': [server_name]})
                    attributes.append({'type': 'name',
                        'vals': ['{}{}'.format(dfs_root, share_name)]})

            results.append(adobj.DFS(attributes))

        return results

    version_to_function = {'v1': _get_dfssharev1, 'v2': _get_dfssharev2}
    results = list()

    for v in version:
        results += version_to_function[v]()

    return results

def get_netou(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(), queried_ouname='*',
        queried_guid=str(), ads_path=str(), full_data=False):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    ou_search_filter = ldapasn1.Filter()
    ou_search_filter['and'] = ldapasn1.And()

    ou_filter = build_equality_match_filter('objectCategory', 'organizationalUnit')
    ou_search_filter['and'][0] = ou_filter

    if queried_ouname:
        if '*' in queried_ouname:
            ou_name_filter = build_substrings_filter('name', queried_ouname)
        else:
            ou_name_filter = build_equality_match_filter('name', queried_ouname)
        ou_search_filter['and'][ou_search_filter['and']._componentValuesSet] = ou_name_filter
    
    if queried_guid:
        guid_filter = build_substrings_filter('gplink', '*{}*'.format(queried_guid))
        ou_search_filter['and'][ou_search_filter['and']._componentValuesSet] = guid_filter

    if full_data:
        attributes = list()
    else:
        attributes = ['distinguishedName']

    results = list()
    for ou in domain_connection.search(searchFilter=ou_search_filter, attributes=attributes):
        if not isinstance(ou, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.OU(ou['attributes']))

    return results

def get_netsite(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(), queried_sitename=str(),
        queried_guid=str(), ads_path=str(), full_data=False):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, 'CN=Sites,CN=Configuration', ads_path)

    site_search_filter = ldapasn1.Filter()
    site_search_filter['and'] = ldapasn1.And()

    site_filter = build_equality_match_filter('objectCategory', 'site')
    site_search_filter['and'][0] = site_filter

    if queried_sitename:
        if '*' in queried_sitename:
            site_name_filter = build_substrings_filter('name', queried_sitename)
        else:
            site_name_filter = build_equality_match_filter('name', queried_sitename)
        site_search_filter['and'][site_search_filter['and']._componentValuesSet] = site_name_filter
    
    if queried_guid:
        guid_filter = build_substrings_filter('gplink', '*{}*'.format(queried_guid))
        site_search_filter['and'][site_search_filter['and']._componentValuesSet] = guid_filter

    if full_data:
        attributes = list()
    else:
        attributes = ['name']

    results = list()
    for site in domain_connection.search(searchFilter=site_search_filter, attributes=attributes):
        if not isinstance(site, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.Site(site['attributes']))

    return results

def get_netsubnet(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(), queried_sitename=str(),
        ads_path=str(), full_data=False):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, 'CN=Subnets,CN=Sites,CN=Configuration', ads_path)

    subnet_search_filter = ldapasn1.Filter()
    subnet_search_filter['and'] = ldapasn1.And()

    subnet_filter = build_equality_match_filter('objectCategory', 'subnet')
    subnet_search_filter['and'][0] = subnet_filter

    if queried_sitename:
        if not queried_sitename.endswith('*'):
            queried_sitename += '*'
        site_name_filter = build_substrings_filter('siteobject', '*CN={}'.format(queried_sitename))
        subnet_search_filter['and'][site_search_filter['and']._componentValuesSet] = site_name_filter
    
    if full_data:
        attributes = list()
    else:
        attributes = ['name', 'siteobject']

    results = list()
    for subnet in domain_connection.search(searchFilter=subnet_search_filter, attributes=attributes):
        if not isinstance(subnet, ldapasn1.SearchResultEntry):
            continue

        results.append(adobj.Subnet(subnet['attributes']))

    return results

def get_netgroupmember(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_groupname=str(),
        queried_sid=str(), queried_domain=str(), ads_path=str(),
        recurse=False, use_matching_rule=False, full_data=False):

    domain_connection = build_domain_connection(domain_controller, domain, user,
            password, lmhash, nthash, queried_domain, ads_path=ads_path)

    def _get_members(_groupname=str(), _sid=str()):
        try:
            if _groupname:
                group = get_netgroup(domain_controller, domain, user, password,
                        lmhash, nthash, queried_groupname=_groupname, full_data=True)[0]
            elif _sid:
                group = get_netgroup(domain_controller, domain, user, password,
                        lmhash, nthash, queried_sid=_sid, full_data=True)[0]
            else:
                queried_sid = get_domainsid(domain_controller, domain, user, password,
                        lmhash, nthash, queried_domain) + '-512'
                group = get_netgroup(domain_controller, domain, user, password,
                    lmhash, nthash, queried_sid=queried_sid, full_data=True)[0]
        except IndexError:
            raise ValueError('The group {} was not found'.format(_groupname))

        members = list()

        if recurse and use_matching_rule:
            group_memberof_filter = build_extensible_match_filter('1.2.840.113556.1.4.1941',
                    'memberof', group.distinguishedname)

            members = get_netuser(domain_controller, domain, user, password,
                    lmhash, nthash, custom_filter=group_memberof_filter)
        else:
            # TODO: range cycling
            for member in group.member:
                dn_filter = build_equality_match_filter('distinguishedname',
                        member)
                members += get_netuser(domain_controller, domain, user, password,
                    lmhash, nthash, custom_filter=dn_filter)
                members += get_netgroup(domain_controller, domain, user, password,
                    lmhash, nthash, custom_filter=dn_filter, full_data=True)

        final_members = list()
        for member in members:
            if full_data:
                final_member = member
            else:
                final_member = adobj.ADObject(list())

            member_dn = member.distinguishedname
            try:
                member_domain = member_dn[member_dn.index('DC='):].replace('DC=', '').replace(',', '.')
            except IndexError:
                member_domain = str()
            is_group = (member.samaccounttype != '805306368')

            attributes = list()
            if queried_domain:
                attributes.append({'type': 'groupdomain', 'vals': [queried_domain]})
            else:
                attributes.append({'type': 'groupdomain', 'vals': [domain]})
            attributes.append({'type': 'groupname', 'vals': [group.name]})
            attributes.append({'type': 'membername', 'vals': [member.samaccountname]})
            attributes.append({'type': 'memberdomain', 'vals': [member_domain]})
            attributes.append({'type': 'isgroup', 'vals': [is_group]})
            attributes.append({'type': 'memberdn', 'vals': [member_dn]})
            attributes.append({'type': 'membersid', 'vals': [member.objectsid]})

            final_member.add_attributes(attributes)

            final_members.append(final_member)

        return final_members

    results = list()
    groups_to_process = [(queried_groupname, queried_sid)]

    while groups_to_process:
        groupname, sid = groups_to_process.pop(0)
        members = _get_members(groupname, sid)

        for member in members:
            results.append(member)
            if (recurse and (not use_matching_rule) and member.isgroup and member.membername):
                groups_to_process.append((member.membername, str()))

    return results

def get_netsession(target_computername, domain, user, password=str(), lmhash=str(), nthash=str()):
    dce = build_dce(domain, user, password, lmhash, nthash, target_computername, r'\srvsvc')
    resp = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)

    results = list()
    for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
        results.append(rpcobj.Session(session))

    return results

def get_netshare(target_computername, domain, user, password=str(),
        lmhash=str(), nthash=str()):
    dce = build_dce(domain, user, password, lmhash, nthash, target_computername, r'\srvsvc')
    resp = srvs.hNetrShareEnum(dce, 1)

    results = list()
    for share in resp['InfoStruct']['ShareInfo']['Level1']['Buffer']:
        results.append(rpcobj.Share(share))

    return results

def get_netloggedon(target_computername, domain, user, password=str(), lmhash=str(), nthash=str()):
    dce = build_dce(domain, user, password, lmhash, nthash, target_computername, r'\wkssvc')
    resp = wkst.hNetrWkstaUserEnum(dce, 1)

    results = list()
    for wksta_user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
        results.append(rpcobj.WkstaUser(wksta_user))

    return results

def get_netlocalgroup(target_computername, domain_controller, domain, user,
        password=str(), lmhash=str(), nthash=str(), queried_groupname=str(),
        list_groups=False, recurse=False):
    from impacket.nt_errors import STATUS_MORE_ENTRIES
    results = list()

    # We first get a handle to the server
    dce = build_dce(domain, user, password, lmhash, nthash, target_computername, r'\samr')
    resp = samr.hSamrConnect(dce)
    server_handle = resp['ServerHandle']

    # We first list every domain in the SAM
    resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
    domains = resp['Buffer']['Buffer']
    domain_handles = dict()
    for local_domain in domains:
        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, local_domain['Name'])
        domain_sid = 'S-1-5-{}'.format('-'.join(str(x) for x in resp['DomainId']['SubAuthority']))
        resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
        domain_handles[domain_sid] = resp['DomainHandle']

    # If we list the groups
    if list_groups:
        # We browse every domain
        for domain_sid, domain_handle in domain_handles.items():
            # We enumerate local groups in every domain
            enumeration_context = 0
            groups = list()
            while True:
                resp = samr.hSamrEnumerateAliasesInDomain(dce, domain_handle,
                        enumerationContext=enumeration_context)
                groups += resp['Buffer']['Buffer']

                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break

            # We get information on every group
            for group in groups:
                resp = samr.hSamrRidToSid(dce, domain_handle, rid=group['RelativeId'])
                sid = 'S-1-5-{}'.format('-'.join(str(x) for x in resp['Sid']['SubAuthority']))

                resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=group['RelativeId'])
                alias_handle = resp['AliasHandle']
                resp = samr.hSamrQueryInformationAlias(dce, alias_handle)

                final_group = rpcobj.Group(resp['Buffer']['General'])
                final_group.add_atributes({'server': target_computername, 'sid': sid})

                results.append(final_group)

                samr.hSamrCloseHandle(dce, alias_handle)

            samr.hSamrCloseHandle(dce, domain_handle)
    # If we query a group
    else:
        queried_group_rid = None
        queried_group_domain_handle = None

        # If the user is looking for a particular group
        if queried_groupname:
            # We look for it in every domain
            for _, domain_handle in domain_handles.items():
                try:
                    resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [queried_groupname])
                    queried_group_rid = resp['RelativeIds']['Element'][0]['Data']
                    queried_group_domain_handle = domain_handle
                    break
                except (impacket.dcerpc.v5.samr.DCERPCSessionError, KeyError, IndexError):
                    continue
            else:
                raise ValueError('The group \'{}\' was not found on the target server'.format(queried_groupname))
        # Otherwise, we look for the local Administrators group
        else:
            queried_group_rid = 544
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, 'BUILTIN')
            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
            queried_group_domain_handle = resp['DomainHandle']

        # We get a handle on the group, and list its members
        try:
            group = samr.hSamrOpenAlias(dce, queried_group_domain_handle, aliasId=queried_group_rid)
            resp = samr.hSamrGetMembersInAlias(dce, group['AliasHandle'])
        except impacket.dcerpc.v5.samr.DCERPCSessionError:
            raise ValueError('The name \'{}\' is not a valid group on the target server'.format(queried_groupname))

        # For every user, we look for information in every local domain
        for member in resp['Members']['Sids']:
            attributes = dict()
            member_rid = member['SidPointer']['SubAuthority'][-1]
            member_sid = 'S-1-5-{}'.format('-'.join(str(x) for x in member['SidPointer']['SubAuthority']))

            attributes['server'] = target_computername
            attributes['sid'] = member_sid

            for domain_sid, domain_handle in domain_handles.items():
                # We've found a local member
                if member_sid.startswith(domain_sid):
                    attributes['isdomain'] = False
                    resp = samr.hSamrQueryInformationDomain(dce, domain_handle)
                    member_domain = resp['Buffer']['General2']['I1']['DomainName']
                    try:
                        resp = samr.hSamrOpenUser(dce, domain_handle, userId=member_rid)
                        member_handle = resp['UserHandle']
                        attributes['isgroup'] = False
                        resp = samr.hSamrQueryInformationUser(dce, member_handle)
                        attributes['name'] = '{}/{}'.format(member_domain, resp['Buffer']['General']['UserName'])
                    except impacket.dcerpc.v5.samr.DCERPCSessionError:
                        resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=member_rid)
                        member_handle = resp['AliasHandle']
                        attributes['isgroup'] = True
                        resp = samr.hSamrQueryInformationAlias(dce, member_handle)
                        attributes['name'] = '{}/{}'.format(member_domain, resp['Buffer']['General']['Name'])
                    attributes['lastlogin'] = str()
                    break
            # It's a domain member
            else:
                attributes['isdomain'] = True
                if domain_controller:
                    try:
                        ad_object = get_adobject(domain_controller, domain, user,
                                password, lmhash, nthash, queried_sid=member_sid)[0]
                        member_dn = ad_object.distinguishedname
                        member_domain = member_dn[member_dn.index('DC='):].replace('DC=', '').replace(',', '.')
                        attributes['name'] = '{}/{}'.format(member_domain, ad_object.name)
                        attributes['isgroup'] = ad_object.isgroup
                        try:
                            attributes['lastlogin'] = ad_object.lastlogon
                        except AttributeError:
                            attributes['lastlogin'] = str()
                    except IndexError:
                        # We did not manage to resolve this SID against the DC
                        attributes['isdomain'] = False
                        attributes['isgroup'] = False
                        attributes['name'] = attributes['sid']
                        attributes['lastlogin'] = str()

            results.append(rpcobj.RPCObject(attributes))

            # If we recurse and the member is a domain group, we query every member
            if domain_controller and recurse and attributes['isdomain'] and attributes['isgroup']:
                for domain_member in get_netgroupmember(domain_controller, domain, user, password,
                        lmhash, nthash, full_data=True, recurse=True, queried_sid=attributes['sid']):
                    domain_member_attributes = dict()
                    domain_member_attributes['isdomain'] = True
                    member_dn = domain_member.distinguishedname
                    member_domain = member_dn[member_dn.index('DC='):].replace('DC=', '').replace(',', '.')
                    domain_member_attributes['name'] = '{}/{}'.format(member_domain, domain_member.name)
                    domain_member_attributes['isgroup'] = domain_member.isgroup
                    domain_member_attributes['isdomain'] = True
                    domain_member_attributes['server'] = attributes['name']
                    domain_member_attributes['sid'] = domain_member.objectsid
                    try:
                        domain_member_attributes['lastlogin'] = ad_object.lastlogon
                    except AttributeError:
                        domain_member_attributes['lastlogin'] = str()
                    results.append(rpcobj.RPCObject(domain_member_attributes))

    return results

