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

    @LDAPRequester._ldap_connection_init
    def get_netpso(self, queried_psoname='*', queried_displayname=str(),
                   queried_domain=str(), ads_path=str()):

        pso_search_filter = '(objectClass=msDS-PasswordSettings)'

        if queried_displayname:
            pso_search_filter += '(displayname={})'.format(queried_displayname)
        else:
            pso_search_filter += '(name={})'.format(queried_psoname)

        pso_search_filter = '(&{})'.format(pso_search_filter)

        return self._ldap_search(pso_search_filter, PSO)

    def get_gpttmpl(self, gpttmpl_path):
        content_io = BytesIO()

        gpttmpl_path_split = gpttmpl_path.split('\\')
        target = self._domain_controller
        share = gpttmpl_path_split[3]
        file_name = '\\'.join(gpttmpl_path_split[4:])

        smb_connection = SMBConnection(remoteName=target, remoteHost=target)
        if self._do_kerberos:
            smb_connection.kerberosLogin(self._user, self._password, self._domain,
                                 self._lmhash, self._nthash)
        else:
            smb_connection.login(self._user, self._password, self._domain,
                                 self._lmhash, self._nthash)

        self._logger.debug('Get File: Share = {0}, file_name ={1}'.format(share, file_name))
        smb_connection.connectTree(share)
        smb_connection.getFile(share, file_name, content_io.write)
        try:
            content = content_io.getvalue().decode('utf-16le')[1:].replace('\r', '')
        except UnicodeDecodeError:
            self._logger.warning('Unicode error: trying utf-8')
            content = content_io.getvalue().decode('utf-8').replace('\r', '')

        gpttmpl_final = GptTmpl(list())
        for l in content.split('\n'):
            if l.startswith('['):
                section_name = l.strip('[]').replace(' ', '').lower()
                gpttmpl_final._attributes_dict[section_name] = Policy(list())
            elif '=' in l:
                property_name, property_values = [x.strip() for x in l.split('=')]
                if ',' in property_values:
                    property_values = property_values.split(',')
                gpttmpl_final._attributes_dict[section_name]._attributes_dict[property_name] = property_values

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
                    self._logger.critical('Could not parse privilegerights from the DC policy, SIDs will not be resolved')
                    return gpttmpl

                members = inspect.getmembers(privilege_rights_policy, lambda x: not(inspect.isroutine(x)))
                with NetRequester(self._domain_controller, self._domain, self._user,
                                  self._password, self._lmhash, self._nthash, self._do_kerberos, self._do_tls) as net_requester:
                    for attr in privilege_rights_policy._attributes_dict:
                        attribute = privilege_rights_policy._attributes_dict[attr]
                        if not isinstance(attribute, list):
                            sids = [attribute]
                        else:
                            sids = attribute
                        resolved_sids = list()
                        for sid in sids:
                            if not sid:
                                continue
                            sid = sid.replace('*', '')
                            try:
                                resolved_sid = net_requester.get_adobject(queried_sid=sid, queried_domain=self._queried_domain)[0]
                            except IndexError:
                                self._logger.warning('We did not manage to resolve this SID ({}) against the DC'.format(sid))
                                resolved_sid = sid
                            else:
                                resolved_sid = resolved_sid.distinguishedname.split(',')[:2]
                                resolved_sid = resolved_sid[1] + '\\' + resolved_sid[0]
                                resolved_sid = resolved_sid.replace('CN=', '')
                            finally:
                                resolved_sids.append(resolved_sid)
                        if len(resolved_sids) == 1:
                            resolved_sids = resolved_sids[0]
                        privilege_rights_policy._attributes_dict[attr] = resolved_sids

                gpttmpl.privilegerights = privilege_rights_policy

                return gpttmpl

    def _get_groupsxml(self, groupsxml_path, gpo_display_name):
        gpo_groups = list()

        content_io = BytesIO()

        groupsxml_path_split = groupsxml_path.split('\\')
        gpo_name = groupsxml_path_split[6]
        target = self._domain_controller
        share = groupsxml_path_split[3]
        file_name = '\\'.join(groupsxml_path_split[4:])

        smb_connection = SMBConnection(remoteName=target, remoteHost=target)
        if self._do_kerberos:
            smb_connection.kerberosLogin(self._user, self._password, self._domain,
                                 self._lmhash, self._nthash)
        else:
            smb_connection.login(self._user, self._password, self._domain,
                                 self._lmhash, self._nthash)

        self._logger.debug('Get File: Share = {0}, file_name ={1}'.format(share, file_name))
        smb_connection.connectTree(share)
        try:
            smb_connection.getFile(share, file_name, content_io.write)
        except SessionError:
            self._logger.warning('Error while getting the file {}, skipping...'.format(file_name))
            return list()

        content = content_io.getvalue().replace(b'\r', b'')
        groupsxml_soup = BeautifulSoup(content.decode('utf-8'), 'xml')
        for group in groupsxml_soup.find_all('Group'):
            members = list()
            memberof = list()

            raw_xml_member = group.Properties.find_all('Member')
            if not raw_xml_member:
                continue

            local_sid = group.Properties.get('groupSid', str())

            if not local_sid:
                if 'administrators' in group.Properties['groupName'].lower():
                    local_sid = 'S-1-5-32-544'
                elif 'remote desktop' in group.Properties['groupName'].lower():
                    local_sid = 'S-1-5-32-555'
                else:
                    local_sid = group.Properties['groupName']
            memberof.append(local_sid)

            for member in raw_xml_member:
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
                gpo_group._attributes_dict['gpodisplayname'] = gpo_display_name
                gpo_group._attributes_dict['gponame'] = gpo_name
                gpo_group._attributes_dict['gpopath'] = groupsxml_path
                gpo_group._attributes_dict['members'] = members
                gpo_group._attributes_dict['memberof'] = memberof

                gpo_groups.append(gpo_group)

        return gpo_groups

    def _get_groupsgpttmpl(self, gpttmpl_path, gpo_display_name):
        gpo_groups = list()

        gpt_tmpl = self.get_gpttmpl(gpttmpl_path)
        gpo_name = gpttmpl_path.split('\\')[6]

        try:
            group_membership = gpt_tmpl.groupmembership
        except AttributeError:
            return list()

        membership = group_membership._attributes_dict

        for ma,mv in membership.items():
            if not mv:
                continue
            members = list()
            memberof = list()
            if ma.lower().endswith('__memberof'):
                members.append(ma.upper().lstrip('*').replace('__MEMBEROF', ''))
                if not isinstance(mv, list):
                    memberof_list = [mv]
                else:
                    memberof_list = mv
                memberof += [x.lstrip('*') for x in memberof_list]
            elif ma.lower().endswith('__members'):
                memberof.append(ma.upper().lstrip('*').replace('__MEMBERS', ''))
                if not isinstance(mv, list):
                    members_list = [mv]
                else:
                    members_list = mv
                members += [x.lstrip('*') for x in members_list]

            if members and memberof:
                gpo_group = GPOGroup(list())
                gpo_group.add_attributes({'gpodisplayname' : gpo_display_name})
                gpo_group.add_attributes({'gponame' : gpo_name})
                gpo_group.add_attributes({'gpopath' : gpttmpl_path})
                gpo_group.add_attributes({'members' : members})
                gpo_group.add_attributes({'memberof' : memberof})

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
                self._logger.warning('Error while getting the file {}, skipping...'.format(gpttmpl_path,))
                pass

        if resolve_sids:
            for gpo_group in results:
                members = gpo_group.members
                memberof = gpo_group.memberof

                resolved_members = list()
                resolved_memberof = list()
                with NetRequester(self._domain_controller, self._domain, self._user,
                                  self._password, self._lmhash, self._nthash, self._do_kerberos, self._do_tls) as net_requester:
                    for member in members:
                        try:
                            resolved_member = net_requester.get_adobject(queried_sid=member, queried_domain=self._queried_domain)[0]
                            resolved_member = resolved_member.distinguishedname
                        except IndexError:
                            self._logger.warning('We did not manage to resolve this SID ({}) against the DC'.format(member))
                            resolved_member = member
                        finally:
                            resolved_members.append(resolved_member)
                    gpo_group._attributes_dict['members'] = resolved_members

                    for member in memberof:
                        try:
                            resolved_member = net_requester.get_adobject(queried_sid=member, queried_domain=self._queried_domain)[0]
                            resolved_member = resolved_member.distinguishedname
                        except IndexError:
                            self._logger.warning('We did not manage to resolve this SID ({}) against the DC'.format(member))
                            resolved_member = member
                        finally:
                            resolved_memberof.append(resolved_member)
                    gpo_group._attributes_dict['memberof'] = memberof = resolved_memberof
        return results

    def find_gpocomputeradmin(self, queried_computername=str(),
                                 queried_ouname=str(), queried_domain=str(),
                                 recurse=False):

        results = list()
        if (not queried_computername) and (not queried_ouname):
            raise ValueError('You must specify either a computer name or an OU name')

        net_requester = NetRequester(self._domain_controller, self._domain, self._user,
                                     self._password, self._lmhash, self._nthash, self._do_kerberos,
                                     self._do_tls)
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

        # Hack to save the base DN for later
        if not queried_domain:
            saved_queried_domain = ','.join('dc={}'.format(x) for x in net_requester._domain.split('.'))[3:]

        gpo_groups = list()
        for target_ou in target_ous:
            ous = net_requester.get_netou(ads_path=target_ou, queried_domain=queried_domain,
                                          full_data=True)
            for ou in ous:
                try:
                    gplinks = ou.gplink.strip('[]').split('][')
                except AttributeError:
                    continue
                for gplink in gplinks:
                    gplink = gplink.split(';')[0]
                    gpo_groups = self.get_netgpogroup(queried_domain=queried_domain,
                                                      ads_path=gplink)
                    for gpo_group in gpo_groups:
                        for member in gpo_group.members:
                            obj = net_requester.get_adobject(queried_sid=member,
                                                             queried_domain=saved_queried_domain)[0]
                            gpo_computer_admin = GPOComputerAdmin(list())
                            gpo_computer_admin.add_attributes({'computername' : queried_computername})
                            gpo_computer_admin.add_attributes({'ou' : target_ou})
                            gpo_computer_admin.add_attributes({'gpodisplayname' : gpo_group.gpodisplayname})
                            gpo_computer_admin.add_attributes({'gpopath' : gpo_group.gpopath})
                            gpo_computer_admin.add_attributes({'objectname' : obj.name})
                            gpo_computer_admin.add_attributes({'objectdn' : obj.distinguishedname})
                            gpo_computer_admin.add_attributes({'objectsid' : obj.objectsid})
                            gpo_computer_admin.add_attributes({'isgroup' : (obj.samaccounttype == 'GROUP_OBJECT')})

                            results.append(gpo_computer_admin)

                            if recurse and gpo_computer_admin.isgroup:
                                groups_to_resolve = [gpo_computer_admin.objectsid]
                                while groups_to_resolve:
                                    group_to_resolve = groups_to_resolve.pop(0)

                                    group_members = net_requester.get_netgroupmember(queried_sid=group_to_resolve,
                                                                                     queried_domain=saved_queried_domain,
                                                                                     full_data=True)
                                    for group_member in group_members:
                                        gpo_computer_admin = GPOComputerAdmin(list())
                                        gpo_computer_admin.add_attributes({'computername' : queried_computername})
                                        gpo_computer_admin.add_attributes({'ou' : target_ou})
                                        gpo_computer_admin.add_attributes({'gpodisplayname' : gpo_group.gpodisplayname})
                                        gpo_computer_admin.add_attributes({'gpopath' : gpo_group.gpopath})
                                        gpo_computer_admin.add_attributes({'objectname' : group_member.samaccountname})
                                        gpo_computer_admin.add_attributes({'objectdn' : group_member.distinguishedname})
                                        gpo_computer_admin.add_attributes({'objectsid' : group_member.objectsid})
                                        gpo_computer_admin.add_attributes({'isgroup' : (group_member.samaccounttype == 'GROUP_OBJECT')})

                                        results.append(gpo_computer_admin)

                                        if gpo_computer_admin.isgroup:
                                            groups_to_resolve.append(group_member.objectsid)

        return results

    def find_gpolocation(self, queried_username=str(), queried_groupname=str(),
                         queried_localgroup=str(), queried_domain=str()):
        results = list()
        net_requester = NetRequester(self._domain_controller, self._domain, self._user,
                                     self._password, self._lmhash, self._nthash, self._do_kerberos,
                                     self._do_tls)
        if queried_username:
                try:
                    user = net_requester.get_netuser(queried_username=queried_username,
                                                     queried_domain=self._queried_domain)[0]
                except IndexError:
                    raise ValueError('Username \'{}\' was not found'.format(queried_username))
                else:
                    target_sid = [user.objectsid]
                    object_sam_account_name = user.samaccountname
                    object_distinguished_name = user.distinguishedname
        elif queried_groupname:
                try:
                    group = net_requester.get_netgroup(queried_groupname=queried_groupname,
                                                       queried_domain=self._queried_domain,
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
                                                              queried_domain=self._queried_domain)[0].objectsid
            except IndexError:
                # We may have the name of the group, but not its sam account name
                self._logger.warning('We may have the name of the group, but not its sam account name.')
                try:
                    object_group_sid = net_requester.get_adobject(queried_name=object_group.samaccountname,
                                                                  queried_domain=self._queried_domain)[0].objectsid
                except IndexError:
                    # Freak accident when someone is a member of a group, but
                    # we can't find the group in the AD
                    self._logger.warning('Freak accident when someone is a member of a group, but we can\'t find the group in the AD,'
                                         'see DEBUG level for more info')
                    self._logger.debug('Dumping the mysterious object = {}'.format(object_group))
                    continue

            target_sid.append(object_group_sid)

        gpo_groups = list()
        for gpo_group in self.get_netgpogroup(queried_domain=queried_domain):
            try:
                for member in gpo_group.members:
                    member = member
                    if not member.upper().startswith('S-1-5'):
                        try:
                            member = net_requester.get_adobject(queried_sam_account_name=member,
                                                                queried_domain=self._queried_domain)[0].objectsid
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
            ous = net_requester.get_netou(queried_domain=self._queried_domain,
                                          queried_guid=gpo_guid, full_data=True)
            for ou in ous:
                ou_distinguishedname = 'LDAP://{}'.format(ou.distinguishedname)
                # TODO: support filters for GPO
                ou_computers = [x.dnshostname for x in \
                        net_requester.get_netcomputer(queried_domain=self._queried_domain,
                                                      ads_path=ou_distinguishedname)]
                gpo_location = GPOLocation(list())
                gpo_location.add_attributes({'objectname' : object_distinguished_name})
                gpo_location.add_attributes({'gponame' : gpo_group.gpodisplayname})
                gpo_location.add_attributes({'gpoguid' : gpo_guid})
                gpo_location.add_attributes({'containername' : ou.distinguishedname})
                gpo_location.add_attributes({'computers' : ou_computers})

                results.append(gpo_location)

        return results

