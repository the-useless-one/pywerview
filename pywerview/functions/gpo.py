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

# Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2021

import codecs
from bs4 import BeautifulSoup
from io import BytesIO

from impacket.smbconnection import SMBConnection, SessionError

from pywerview.objects.adobjects import *
from pywerview.requester import LDAPRequester
from pywerview.functions.net import NetRequester

class GPORequester(LDAPRequester):

    @LDAPRequester._ldap_connection_init
    def get_netgpo(self, queried_gponame='*', queried_displayname=str(),
                   queried_domain=str(), ads_path=str()):

        gpo_search_filter = '(objectCategory=groupPolicyContainer)'

        if queried_displayname:
            gpo_search_filter += '(displayname={})'.format(queried_displayname)
        else:
            gpo_search_filter += '(name={})'.format(queried_gponame)

        gpo_search_filter = '(&{})'.format(gpo_search_filter)

        return self._ldap_search(gpo_search_filter, GPO)

    def get_gpttmpl(self, gpttmpl_path):
        content_io = BytesIO()

        gpttmpl_path_split = gpttmpl_path.split('\\')
        target = self._domain_controller
        share = gpttmpl_path_split[3]
        file_name = '\\'.join(gpttmpl_path_split[4:])

        smb_connection = SMBConnection(remoteName=target, remoteHost=target)
        # TODO: kerberos login
        smb_connection.login(self._user, self._password, self._domain,
                             self._lmhash, self._nthash)

        smb_connection.connectTree(share)
        smb_connection.getFile(share, file_name, content_io.write)
        try:
            content = codecs.decode(content_io.getvalue(), 'utf-16le')[1:].replace('\r', '')
        except UnicodeDecodeError:
            content = str(content_io.getvalue()).replace('\r', '')

        gpttmpl_final = GptTmpl(list())
        for l in content.split('\n'):
            if l.startswith('['):
                section_name = l.strip('[]').replace(' ', '').lower()
                setattr(gpttmpl_final, section_name, Policy(list()))
            elif '=' in l:
                property_name, property_values = [x.strip() for x in l.split('=')]
                if ',' in property_values:
                    property_values = property_values.split(',')
                try:
                    setattr(getattr(gpttmpl_final, section_name), property_name, property_values)
                except UnicodeEncodeError:
                    property_name = property_name.encode('utf-8')
                    setattr(getattr(gpttmpl_final, section_name), property_name, property_values)

        return gpttmpl_final

    def get_domainpolicy(self, source='domain', queried_domain=str(),
                         resolve_sids=False):
        if source == 'domain':
            queried_gponame = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        elif source == 'dc':
            queried_gponame = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        gpo = self.get_netgpo(queried_domain=queried_domain, queried_gponame=queried_gponame)[0]

        gpttmpl_path = '{}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf'.format(gpo.gpcfilesyspath)
        gpttmpl = self.get_gpttmpl(gpttmpl_path)

        if source == 'domain':
            return gpttmpl
        elif source == 'dc':
            if not resolve_sids:
                return gpttmpl
            else:
                import inspect
                try:
                    privilege_rights_policy = gpttmpl.privilegerights
                except AttributeError:
                    return gpttmpl

                members = inspect.getmembers(privilege_rights_policy, lambda x: not(inspect.isroutine(x)))
                with NetRequester(self._domain_controller, self._domain, self._user,
                                  self._password, self._lmhash, self._nthash) as net_requester:
                    for member in members:
                        if member[0].startswith('_'):
                            continue
                        if not isinstance(member[1], list):
                            sids = [member[1]]
                        else:
                            sids = member[1]
                        resolved_sids = list()
                        for sid in sids:
                            if not sid:
                                continue
                            try:
                                resolved_sid = net_requester.get_adobject(queried_sid=sid, queried_domain=queried_domain)[0]
                            except IndexError:
                                resolved_sid = sid
                            else:
                                resolved_sid = resolved_sid.distinguishedname.split(',')[:2]
                                resolved_sid = '{}\\{}'.format(resolved_sid[1], resolved_sid[0])
                                resolved_sid = resolved_sid.replace('CN=', '')
                                resolved_sids.append(resolved_sid)
                        if len(resolved_sids) == 1:
                            resolved_sids = resolved_sids[0]
                        setattr(privilege_rights_policy, member[0], resolved_sids)

                gpttmpl.privilegerights = privilege_rights_policy

                return gpttmpl

    def _get_groupsxml(self, groupsxml_path, gpo_display_name):
        gpo_groups = list()

        content_io = StringIO()

        groupsxml_path_split = groupsxml_path.split('\\')
        gpo_name = groupsxml_path_split[6]
        target = self._domain_controller
        share = groupsxml_path_split[3]
        file_name = '\\'.join(groupsxml_path_split[4:])

        smb_connection = SMBConnection(remoteName=target, remoteHost=target)
        # TODO: kerberos login
        smb_connection.login(self._user, self._password, self._domain,
                             self._lmhash, self._nthash)

        smb_connection.connectTree(share)
        try:
            smb_connection.getFile(share, file_name, content_io.write)
        except SessionError:
            return list()

        content = content_io.getvalue().replace('\r', '')
        groupsxml_soup = BeautifulSoup(content, 'xml')

        for group in groupsxml_soup.find_all('Group'):
            members = list()
            memberof = list()
            local_sid = group.Properties.get('groupSid', str())
            if not local_sid:
                if 'administrators' in group.Properties['groupName'].lower():
                    local_sid = 'S-1-5-32-544'
                elif 'remote desktop' in group.Properties['groupName'].lower():
                    local_sid = 'S-1-5-32-555'
                else:
                    local_sid = group.Properties['groupName']
            memberof.append(local_sid)

            for member in group.Properties.find_all('Member'):
                if not member['action'].lower() == 'add':
                    continue
                if member['sid']:
                    members.append(member['sid'])
                else:
                    members.append(member['name'])

            if members or memberof:
                # TODO: implement filter support (seems like a pain in the ass,
                # I'll do it if the feature is asked). PowerView also seems to
                # have the barest support for filters, so ¯\_(ツ)_/¯

                gpo_group = GPOGroup(list())
                setattr(gpo_group, 'gpodisplayname', gpo_display_name)
                setattr(gpo_group, 'gponame', gpo_name)
                setattr(gpo_group, 'gpopath', groupsxml_path)
                setattr(gpo_group, 'members', members)
                setattr(gpo_group, 'memberof', memberof)

                gpo_groups.append(gpo_group)

        return gpo_groups

    def _get_groupsgpttmpl(self, gpttmpl_path, gpo_display_name):
        import inspect
        gpo_groups = list()

        gpt_tmpl = self.get_gpttmpl(gpttmpl_path)
        gpo_name = gpttmpl_path.split('\\')[6]

        try:
            group_membership = gpt_tmpl.groupmembership
        except AttributeError:
            return list()

        membership = inspect.getmembers(group_membership, lambda x: not(inspect.isroutine(x)))
        for m in membership:
            if not m[1]:
                continue
            members = list()
            memberof = list()
            if m[0].lower().endswith('__memberof'):
                members.append(m[0].upper().lstrip('*').replace('__MEMBEROF', ''))
                if not isinstance(m[1], list):
                    memberof_list = [m[1]]
                else:
                    memberof_list = m[1]
                memberof += [x.lstrip('*') for x in memberof_list]
            elif m[0].lower().endswith('__members'):
                memberof.append(m[0].upper().lstrip('*').replace('__MEMBERS', ''))
                if not isinstance(m[1], list):
                    members_list = [m[1]]
                else:
                    members_list = m[1]
                members += [x.lstrip('*') for x in members_list]

            if members and memberof:
                gpo_group = GPOGroup(list())
                setattr(gpo_group, 'gpodisplayname', gpo_display_name)
                setattr(gpo_group, 'gponame', gpo_name)
                setattr(gpo_group, 'gpopath', gpttmpl_path)
                setattr(gpo_group, 'members', members)
                setattr(gpo_group, 'memberof', memberof)

                gpo_groups.append(gpo_group)

        return gpo_groups

    def get_netgpogroup(self, queried_gponame='*', queried_displayname=str(),
                        queried_domain=str(), ads_path=str(), resolve_sids=False):
        results = list()
        gpos = self.get_netgpo(queried_gponame=queried_gponame,
                               queried_displayname=queried_displayname,
                               queried_domain=queried_domain,
                               ads_path=ads_path)

        for gpo in gpos:
            gpo_display_name = gpo.displayname

            groupsxml_path = '{}\\MACHINE\\Preferences\\Groups\\Groups.xml'.format(gpo.gpcfilesyspath)
            gpttmpl_path = '{}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf'.format(gpo.gpcfilesyspath)

            results += self._get_groupsxml(groupsxml_path, gpo_display_name)
            try:
                results += self._get_groupsgpttmpl(gpttmpl_path, gpo_display_name)
            except SessionError:
                # If the GptTmpl file doesn't exist, we skip this
                pass

        if resolve_sids:
            for gpo_group in results:
                members = gpo_group.members
                memberof = gpo_group.memberof

                resolved_members = list()
                resolved_memberof = list()
                with NetRequester(self._domain_controller, self._domain, self._user,
                                  self._password, self._lmhash, self._nthash) as net_requester:
                    for member in members:
                        try:
                            resolved_member = net_requester.get_adobject(queried_sid=member, queried_domain=queried_domain)[0]
                            resolved_member = resolved_member.distinguishedname.split(',')
                            resolved_member_domain = '.'.join(resolved_member[1:])
                            resolved_member = '{}\\{}'.format(resolved_member_domain, resolved_member[0])
                            resolved_member = resolved_member.replace('CN=', '').replace('DC=', '')
                        except IndexError:
                            resolved_member = member
                        finally:
                            resolved_members.append(resolved_member)
                    gpo_group.members = resolved_members

                    for member in memberof:
                        try:
                            resolved_member = net_requester.get_adobject(queried_sid=member, queried_domain=queried_domain)[0]
                            resolved_member = resolved_member.distinguishedname.split(',')[:2]
                            resolved_member = '{}\\{}'.format(resolved_member[1], resolved_member[0])
                            resolved_member = resolved_member.replace('CN=', '').replace('DC=', '')
                        except IndexError:
                            resolved_member = member
                        finally:
                            resolved_memberof.append(resolved_member)
                    gpo_group.memberof = memberof = resolved_memberof

        return results

    def find_gpocomputeradmin(self, queried_computername=str(),
                                 queried_ouname=str(), queried_domain=str(),
                                 recurse=False):

        results = list()
        if (not queried_computername) and (not queried_ouname):
            raise ValueError('You must specify either a computer name or an OU name')

        net_requester = NetRequester(self._domain_controller, self._domain, self._user,
                                     self._password, self._lmhash, self._nthash)
        if queried_computername:
            computers = net_requester.get_netcomputer(queried_computername=queried_computername,
                                                      queried_domain=queried_domain,
                                                      full_data=True)
            if not computers:
                raise ValueError('Computer {} not found'.format(queried_computername))

            target_ous = list()
            for computer in computers:
                dn = computer.distinguishedname
                for x in dn.split(','):
                    if x.startswith('OU='):
                        target_ous.append(dn[dn.find(x):])
        else:
            target_ous = [queried_ouname]

        gpo_groups = list()
        for target_ou in target_ous:
            ous = net_requester.get_netou(ads_path=target_ou, queried_domain=queried_domain,
                                          full_data=True)

            for ou in ous:
                for gplink in ou.gplink.strip('[]').split(']['):
                    gplink = gplink.split(';')[0]
                    gpo_groups = self.get_netgpogroup(queried_domain=queried_domain,
                                                      ads_path=gplink)
                    for gpo_group in gpo_groups:
                        for member in gpo_group.members:
                            obj = net_requester.get_adobject(queried_sid=member,
                                                             queried_domain=queried_domain)[0]
                            gpo_computer_admin = GPOComputerAdmin(list())
                            setattr(gpo_computer_admin, 'computername', queried_computername)
                            setattr(gpo_computer_admin, 'ou', target_ou)
                            setattr(gpo_computer_admin, 'gpodisplayname', gpo_group.gpodisplayname)
                            setattr(gpo_computer_admin, 'gpopath', gpo_group.gpopath)
                            setattr(gpo_computer_admin, 'objectname', obj.name)
                            setattr(gpo_computer_admin, 'objectdn', obj.distinguishedname)
                            setattr(gpo_computer_admin, 'objectsid', member)
                            setattr(gpo_computer_admin, 'isgroup', (obj.samaccounttype != '805306368'))

                            results.append(gpo_computer_admin)

                            if recurse and gpo_computer_admin.isgroup:
                                groups_to_resolve = [gpo_computer_admin.objectsid]
                                while groups_to_resolve:
                                    group_to_resolve = groups_to_resolve.pop(0)
                                    group_members = net_requester.get_netgroupmember(queried_sid=group_to_resolve,
                                                                                     queried_domain=queried_domain,
                                                                                     full_data=True)
                                    for group_member in group_members:
                                        gpo_computer_admin = GPOComputerAdmin(list())
                                        setattr(gpo_computer_admin, 'computername', queried_computername)
                                        setattr(gpo_computer_admin, 'ou', target_ou)
                                        setattr(gpo_computer_admin, 'gpodisplayname', gpo_group.gpodisplayname)
                                        setattr(gpo_computer_admin, 'gpopath', gpo_group.gpopath)
                                        setattr(gpo_computer_admin, 'objectname', group_member.samaccountname)
                                        setattr(gpo_computer_admin, 'objectdn', group_member.distinguishedname)
                                        setattr(gpo_computer_admin, 'objectsid', member)
                                        setattr(gpo_computer_admin, 'isgroup', (group_member.samaccounttype != '805306368'))

                                        results.append(gpo_computer_admin)

                                        if gpo_computer_admin.isgroup:
                                            groups_to_resolve.append(group_member.objectsid)

        return results

    def find_gpolocation(self, queried_username=str(), queried_groupname=str(),
                         queried_localgroup=str(), queried_domain=str()):
        results = list()
        net_requester = NetRequester(self._domain_controller, self._domain, self._user,
                                     self._password, self._lmhash, self._nthash)
        if queried_username:
                try:
                    user = net_requester.get_netuser(queried_username=queried_username,
                                                     queried_domain=queried_domain)[0]
                except IndexError:
                    raise ValueError('Username \'{}\' was not found'.format(queried_username))
                else:
                    target_sid = [user.objectsid]
                    object_sam_account_name = user.samaccountname
                    object_distinguished_name = user.distinguishedname
        elif queried_groupname:
                try:
                    group = net_requester.get_netgroup(queried_groupname=queried_groupname,
                                                       queried_domain=queried_domain,
                                                       full_data=True)[0]
                except IndexError:
                    raise ValueError('Group name \'{}\' was not found'.format(queried_groupname))
                else:
                    target_sid = [group.objectsid]
                    object_sam_account_name = group.samaccountname
                    object_distinguished_name = group.distinguishedname
        else:
            raise ValueError('You must specify either a username or a group name')

        if 'admin' in queried_localgroup.lower():
            local_sid = 'S-1-5-32-544'
        elif 'rdp' in queried_localgroup.lower():
            local_sid = 'S-1-5-32-555'
        elif queried_localgroup.upper().startswith('S-1-5'):
            local_sid = queried_localgroup
        else:
            raise ValueError('The queried local group must be in \'Administrators\', ' \
                    '\'RDP\', or a \'S-1-5\' type SID')

        object_groups = net_requester.get_netgroup(queried_username=object_sam_account_name,
                                                   queried_domain=queried_domain)
        for object_group in object_groups:
            try:
                object_group_sid = net_requester.get_adobject(queried_sam_account_name=object_group.samaccountname,
                                                              queried_domain=queried_domain)[0].objectsid
            except IndexError:
                # We may have the name of the group, but not its sam account name
                try:
                    object_group_sid = net_requester.get_adobject(queried_name=object_group.samaccountname,
                                                                  queried_domain=queried_domain)[0].objectsid
                except IndexError:
                    # Freak accident when someone is a member of a group, but
                    # we can't find the group in the AD
                    continue

            target_sid.append(object_group_sid)

        gpo_groups = list()
        for gpo_group in self.get_netgpogroup(queried_domain=queried_domain):
            try:
                for member in gpo_group.members:
                    if not member.upper().startswith('S-1-5'):
                        try:
                            member = net_requester.get_adobject(queried_sam_account_name=member,
                                                                queried_domain=queried_domain)[0].objectsid
                        except (IndexError, AttributeError):
                            continue
                    if (member.upper() in target_sid) or (member.lower() in target_sid):
                        if (local_sid.upper() in gpo_group.memberof) or \
                                (local_sid.lower() in gpo_group.memberof):
                            gpo_groups.append(gpo_group)
                            break
            except AttributeError:
                continue

        for gpo_group in gpo_groups:
            gpo_guid = gpo_group.gponame
            ous = net_requester.get_netou(queried_domain=queried_domain,
                                          queried_guid=gpo_guid, full_data=True)
            for ou in ous:
                # TODO: support filters for GPO
                ou_computers = [x.dnshostname for x in \
                        net_requester.get_netcomputer(queried_domain=queried_domain,
                                                      ads_path=ou.distinguishedname)]
                gpo_location = GPOLocation(list())
                setattr(gpo_location, 'objectname', object_distinguished_name)
                setattr(gpo_location, 'gponame', gpo_group.gpodisplayname)
                setattr(gpo_location, 'gpoguid', gpo_guid)
                setattr(gpo_location, 'containername', ou.distinguishedname)
                setattr(gpo_location, 'computers', ou_computers)

                results.append(gpo_location)

        return results

