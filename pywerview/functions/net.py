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

from datetime import datetime, timedelta
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5 import wkst, srvs, samr
from impacket.dcerpc.v5.samr import DCERPCSessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
from bs4 import BeautifulSoup
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import *
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK
from impacket.ldap.ldaptypes import LDAP_SERVER_SD_FLAGS, LDAP_SID, SR_SECURITY_DESCRIPTOR

from pywerview.requester import LDAPRPCRequester
import pywerview.objects.adobjects as adobj
import pywerview.objects.rpcobjects as rpcobj
import pywerview.functions.misc
import pywerview.formatters as fmt

class NetRequester(LDAPRPCRequester):
    def _resolve_sid(self, sid, sid_mapping, attribute=['distinguishedname']):
        try:
            resolved_sid = sid_mapping[sid]
        except KeyError:
            self._logger.warning('SID ({}) is not a well known or already resolved SID'.format(sid))
            try:
                resolved_sid = self.get_adobject(queried_sid=sid, queried_domain=self._queried_domain,
                                                 attributes=attribute)[0].distinguishedname
                self._logger.debug('SID ({0}) is ({1})'.format(sid, resolved_sid))
            except IndexError:
                self._logger.warning('We did not manage to resolve this SID ({}) against the DC'.format(sid))
                resolved_sid = sid
        finally:
            sid_mapping[sid] = resolved_sid

        return resolved_sid

    @LDAPRPCRequester._ldap_connection_init
    def get_netpki(self, queried_domain=str(), queried_ca_name=str(), resolve_sids=False, full_data=False):

        # This function is mostly based on the dumpADCS() one within impacket's ntlmrelayx
        # credit goes to the multiple contributors!
        if full_data:
            attributes=list()
        else:
            attributes = ["certificateTemplates", "displayName", "dNSHostName", "name",
                          "msPKI-Enrollment-Servers", "nTSecurityDescriptor"]

        if queried_ca_name:
            ldap_filter = '(&(objectClass=pKIEnrollmentService)(displayname={}))'.format(queried_ca_name)
        else:
            ldap_filter = '(objectClass=pKIEnrollmentService)'

        controls = security_descriptor_control(criticality=True, sdflags=LDAP_SERVER_SD_FLAGS.DACL_SECURITY_INFORMATION.value)
        base_dn = self._base_dn
        self._base_dn = self._server_info.other['configurationNamingContext'][0]
        objectpki_raw = self._ldap_search(ldap_filter, adobj.PKIEnrollmentService, attributes=attributes, controls=controls)
        self._base_dn = base_dn

        sid_mapping = adobj.ADObject._well_known_sids.copy()
        objectpki = list()
        for pki in objectpki_raw:
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(pki.ntsecuritydescriptor)

            enrollment_principals = list()
            # AccessAllowedObject = 0x05
            for ace in (a for a in sd["Dacl"]["Data"] if a["AceType"] == 0x05):
                sid = format_sid(ace["Ace"]["Sid"].getData())
                if ace["Ace"]["Flags"] == 2:
                    uuid = format_uuid_le(ace["Ace"]["InheritedObjectType"])[1:-1].lower()
                    self._logger.log(self._logger.ULTRA, "UUID found in InheritedObjectType: {}".format(uuid))
                elif ace["Ace"]["Flags"] == 1:
                    uuid = format_uuid_le(ace["Ace"]["ObjectType"])[1:-1].lower()
                    self._logger.log(self._logger.ULTRA, "UUID found in ObjectType: {}".format(uuid))
                else:
                    continue

                if uuid in adobj.PKIEnrollmentService._enrollment_uuids.values():
                    if resolve_sids:
                        resolved_sid = self._resolve_sid(sid, sid_mapping)
                    else:
                        resolved_sid = sid
                    enrollment_principals.append(resolved_sid)
                    pki.add_attributes({'allowedprincipals': enrollment_principals})
                else:
                    self._logger.log(self._logger.ULTRA, "UUID is not a known enrollment UUID: {}".format(uuid))
                    continue
            if not full_data:
                pki._attributes_dict.pop("ntsecuritydescriptor")
            objectpki.append(pki)
        return objectpki

    @LDAPRPCRequester._ldap_connection_init
    def get_netcerttmpl(self, queried_domain=str(), resolve_sids=False, full_data=False, queried_ca_name=str()):

        # This function is mostly based on the dumpADCS() one within impacket's ntlmrelayx
        # credit goes to the multiple contributors!
        base_dn = self._base_dn
        if queried_ca_name:
            self._logger.debug('Queried CA: {}'.format(queried_ca_name))
            ldap_filter = '(&(objectClass=pKIEnrollmentService)(displayname={}))'.format(queried_ca_name)
            attributes = ["certificateTemplates"]
            self._base_dn = self._server_info.other['configurationNamingContext'][0]
            try:
                queried_templates = self._ldap_search(ldap_filter, adobj.PKIEnrollmentService,
                                    attributes=attributes)[0].certificatetemplates
                self._logger.debug('Retrieved certificat templates : {}'.format(queried_templates))
            except IndexError:
                self._logger.critical('We did not manage to find this CA, please specify a valid name')
                raise ValueError('pKIEnrollmentService {} was not found'.format(queried_ca_name))
            self._base_dn = base_dn

        if full_data:
            attributes=list()
        else:
            attributes = ["msPKI-Enrollment-Flag", "name", "nTSecurityDescriptor", "pKIExtendedKeyUsage"]

        controls = security_descriptor_control(criticality=True, sdflags=LDAP_SERVER_SD_FLAGS.DACL_SECURITY_INFORMATION.value)
        config_naming_context = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{}'.format(self._server_info.other['configurationNamingContext'][0])
        self._base_dn = config_naming_context
        ldap_filter = '(objectClass=pKICertificateTemplate)'
        object_cert_template_raw = self._ldap_search(ldap_filter, adobj.PKICertificateTemplate, attributes=attributes, controls=controls)
        self._base_dn = base_dn

        sid_mapping = adobj.ADObject._well_known_sids.copy()
        object_cert_template = list()
        for cert_template in object_cert_template_raw:
            if queried_ca_name:
                if cert_template.name not in queried_templates:
                    self._logger.debug('{0} is not a template of {1}, skipping'.format(cert_template.name, queried_ca_name))
                    continue
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(cert_template.ntsecuritydescriptor)

            enrollment_principals = list()
            # AccessAllowedObject = 0x05
            for ace in (a for a in sd["Dacl"]["Data"] if a["AceType"] == 0x05):
                sid = format_sid(ace["Ace"]["Sid"].getData())
                if ace["Ace"]["Flags"] == 2:
                    uuid = format_uuid_le(ace["Ace"]["InheritedObjectType"])[1:-1].lower()
                    self._logger.log(self._logger.ULTRA, "UUID found in InheritedObjectType: {}".format(uuid))
                elif ace["Ace"]["Flags"] == 1:
                    uuid = format_uuid_le(ace["Ace"]["ObjectType"])[1:-1].lower()
                    self._logger.log(self._logger.ULTRA, "UUID found in ObjectType: {}".format(uuid))
                else:
                    continue

                if uuid in adobj.PKICertificateTemplate._enrollment_uuids.values():
                    if resolve_sids:
                        resolved_sid = self._resolve_sid(sid, sid_mapping)
                    else:
                        resolved_sid = sid
                    enrollment_principals.append(resolved_sid)
                    cert_template.add_attributes({'allowedprincipals': enrollment_principals})
                else:
                    self._logger.log(self._logger.ULTRA, "UUID is not a known enrollment UUID: {}".format(uuid))
                    continue
            if not full_data:
                cert_template._attributes_dict.pop("ntsecuritydescriptor")
            object_cert_template.append(cert_template)
        return object_cert_template

    @LDAPRPCRequester._ldap_connection_init
    def get_adobject(self, queried_domain=str(), queried_sid=str(),
                     queried_name=str(), queried_sam_account_name=str(),
                     ads_path=str(), attributes=list(), custom_filter=str()):
        for attr_desc, attr_value in (('objectSid', queried_sid), ('name', escape_filter_chars(queried_name)),
                                      ('samAccountName', escape_filter_chars(queried_sam_account_name))):
            if attr_value:
                object_filter = '(&({}={}){})'.format(attr_desc, attr_value, custom_filter)
                break
        else:
            object_filter = '(&(name=*){})'.format(custom_filter)

        return self._ldap_search(object_filter, adobj.ADObject, attributes=attributes)
 
    @LDAPRPCRequester._ldap_connection_init
    def get_objectowner(self, queried_domain=str(), queried_sid=str(),
                     queried_name=str(), queried_sam_account_name=str(),
                     ads_path=str(), custom_filter=str(), resolve_sids=False):
        for attr_desc, attr_value in (('objectSid', queried_sid), ('name', escape_filter_chars(queried_name)),
                                      ('samAccountName', escape_filter_chars(queried_sam_account_name))):
            if attr_value:
                object_filter = '(&({}={}){})'.format(attr_desc, attr_value, custom_filter)
                break
        else:
            object_filter = '(&(name=*){})'.format(custom_filter)

        attributes = ['ntsecuritydescriptor','distinguishedname']

        # The control is used to get access to ntSecurityDescriptor with an
        # unprivileged user, see https://stackoverflow.com/questions/40771503/selecting-the-ad-ntsecuritydescriptor-attribute-as-a-non-admin/40773088
        # /!\ May break pagination from what I've read (see Stack Overflow answer)
        controls = security_descriptor_control(criticality=True, sdflags=LDAP_SERVER_SD_FLAGS.OWNER_SECURITY_INFORMATION.value)

        objectowners_raw = self._ldap_search(object_filter, adobj.ADObject, attributes=attributes, controls=controls)
        objectowners = list()
        if resolve_sids:
            sid_mapping = adobj.ADObject._well_known_sids.copy()

        for objectowner in objectowners_raw:
            # Sometimes, admins mess with objects, we skip if the object does not have ntsecuritydescriptor
            if not objectowner.ntsecuritydescriptor:
                self._logger.debug("Skipping an object because it does not have a ntsecuritydescriptor attributes")
                continue
            result = adobj.ObjectOwner(list())
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(objectowner.ntsecuritydescriptor)
            sid = format_sid(sd['OwnerSid'].getData())
            if resolve_sids:
                resolved_sid = self._resolve_sid(sid, sid_mapping)
            else:
                resolved_sid = sid
            result.add_attributes({'distinguishedname': objectowner.distinguishedname})
            result.add_attributes({'objectowner': resolved_sid})
            objectowners.append(result)
        return objectowners

    @LDAPRPCRequester._ldap_connection_init
    def get_netgmsa(self, queried_domain=str(), queried_sid=str(),
                     queried_name=str(), queried_sam_account_name=str(),
                     ads_path=str(), resolve_sids=False):
        filter_objectclass = '(ObjectClass=msDS-GroupManagedServiceAccount)'
        attributes = ['samaccountname', 'distinguishedname', 'objectsid', 'description',
                      'msds-managedpassword', 'msds-groupmsamembership', 'useraccountcontrol']

        if not self._ldap_connection.server.ssl:
            self._logger.warning('LDAP connection is not encrypted, we can\'t ask '\
                    'for msds-managedpassword, removing from list of attributes')
            attributes.remove('msds-managedpassword')

        for attr_desc, attr_value in (('objectSid', queried_sid), ('name', escape_filter_chars(queried_name)),
                                      ('samAccountName', escape_filter_chars(queried_sam_account_name))):
            if attr_value:
                object_filter = '(&({}={}){})'.format(attr_desc, attr_value, filter_objectclass)
                break
        else:
            object_filter = '(&(name=*){})'.format(filter_objectclass)

        sid_mapping = adobj.ADObject._well_known_sids.copy()
        gmsa = self._ldap_search(object_filter, adobj.GMSAAccount, attributes=attributes)

        # In this loop, we resolve SID (if true) and we populate 'enabled' attribute
        for i, adserviceaccount in enumerate(gmsa):
            if resolve_sids:
                results = list()
                for sid in getattr(adserviceaccount, 'msds-groupmsamembership'):
                    resolved_sid = self._resolve_sid(sid, sid_mapping)
                    results.append(resolved_sid)
                gmsa[i].add_attributes({'msds-groupmsamembership': results})
            gmsa[i].add_attributes({'Enabled': 'ACCOUNTDISABLE' not in adserviceaccount.useraccountcontrol})
            gmsa[i]._attributes_dict.pop('useraccountcontrol')

        return gmsa

    @LDAPRPCRequester._ldap_connection_init
    def get_netsmsa(self, queried_domain=str(), queried_sid=str(),
                     queried_name=str(), queried_sam_account_name=str(),
                     ads_path=str()):

        filter_objectclass = '(ObjectClass=msDS-ManagedServiceAccount)'
        attributes = ['samaccountname', 'distinguishedname', 'objectsid', 'description',
                      'msds-hostserviceaccountbl', 'useraccountcontrol']
        for attr_desc, attr_value in (('objectSid', queried_sid), ('name', escape_filter_chars(queried_name)),
                                      ('samAccountName', escape_filter_chars(queried_sam_account_name))):
            if attr_value:
                object_filter = '(&({}={}){})'.format(attr_desc, attr_value, filter_objectclass)
                break
        else:
            object_filter = '(&(name=*){})'.format(filter_objectclass)

        smsas = self._ldap_search(object_filter, adobj.SMSAAccount, attributes=attributes)

        # In this loop, we populate 'enabled' attribute
        for i, adserviceaccount in enumerate(smsas):
            smsas[i].add_attributes({'Enabled': 'ACCOUNTDISABLE' not in adserviceaccount.useraccountcontrol})
            smsas[i]._attributes_dict.pop('useraccountcontrol')

        return smsas

    @LDAPRPCRequester._ldap_connection_init
    def get_objectacl(self, queried_domain=str(), queried_sid=str(),
                     queried_name=str(), queried_sam_account_name=str(),
                     ads_path=str(), sacl=False, rights_filter=str(),
                     resolve_sids=False, resolve_guids=False, custom_filter=str()):
        for attr_desc, attr_value in (('objectSid', queried_sid), ('name', escape_filter_chars(queried_name)),
                                      ('samAccountName', escape_filter_chars(queried_sam_account_name))):
            if attr_value:
                object_filter = '(&({}={}){})'.format(attr_desc, attr_value, custom_filter)
                break
        else:
            object_filter = '(&(name=*){})'.format(custom_filter)

        guid_map = dict()
        # This works on a mono-domain forest, must be tested on a more complex one
        if resolve_guids:
            # Dirty fix to get base DN even if custom ADS path was given
            len_base_dn = len(self._base_dn.split(','))
            base_dn = ','.join(self._base_dn.split(',')[-len_base_dn:])
            guid_map = {'{00000000-0000-0000-0000-000000000000}': 'All'}
            for o in self.get_adobject(ads_path=self._server_info.other['schemaNamingContext'][0],
                    attributes=['name', 'schemaIDGUID'], custom_filter='(schemaIDGUID=*)'):
                        guid_map['{}'.format(format_uuid_le(o.schemaidguid))] = o.name

            for o in self.get_adobject(ads_path='CN=Extended-Rights,{}'.format(self._server_info.other['configurationNamingContext'][0]),
                    attributes=['name', 'rightsGuid'], custom_filter='(objectClass=controlAccessRight)'):
                        guid_map['{{{}}}'.format(o.rightsguid.lower())] = o.name
            self._base_dn = base_dn

        attributes = ['distinguishedname', 'objectsid', 'ntsecuritydescriptor']

        if sacl:
            controls = list()
            acl_type = 'Sacl'
        else:
            # The control is used to get access to ntSecurityDescriptor with an
            # unprivileged user, see https://stackoverflow.com/questions/40771503/selecting-the-ad-ntsecuritydescriptor-attribute-as-a-non-admin/40773088
            # /!\ May break pagination from what I've read (see Stack Overflow answer)
            sdflags = LDAP_SERVER_SD_FLAGS.OWNER_SECURITY_INFORMATION.value | \
                      LDAP_SERVER_SD_FLAGS.GROUP_SECURITY_INFORMATION.value | \
                      LDAP_SERVER_SD_FLAGS.DACL_SECURITY_INFORMATION.value
            controls = security_descriptor_control(criticality=True, sdflags=sdflags)
            acl_type = 'Dacl'

        security_descriptors = self._ldap_search(object_filter, adobj.ADObject,
                attributes=attributes, controls=controls)

        acl = list()

        rights_to_guid = {'reset-password': '{00299570-246d-11d0-a768-00aa006e0529}',
                'write-members': '{bf9679c0-0de6-11d0-a285-00aa003049e2}',
                'allowed-to-authenticate':'{68b1d179-0d15-4d4f-ab71-46152e79a7bc}',
                'all': '{00000000-0000-0000-0000-000000000000}'}
        guid_filter = rights_to_guid.get(rights_filter, None)

        if resolve_sids:
            sid_mapping = adobj.ADObject._well_known_sids.copy()

        for security_descriptor in security_descriptors:
            sd = SR_SECURITY_DESCRIPTOR()
            try:
                sd.fromString(security_descriptor.ntsecuritydescriptor)
            except TypeError:
                continue
            for ace in sd[acl_type]['Data']:
                if guid_filter:
                    try:
                        object_type = format_uuid_le(ace['Ace']['ObjectType']) if ace['Ace']['ObjectType'] else '{00000000-0000-0000-0000-000000000000}'
                    except KeyError:
                        continue
                    if object_type != guid_filter:
                        continue
                attributes = dict()
                attributes['objectdn'] = security_descriptor.distinguishedname
                attributes['objectsid'] = security_descriptor.objectsid
                attributes['acetype'] = ace['TypeName']
                attributes['binarysize'] = ace['AceSize']
                attributes['aceflags'] = fmt.format_ace_flags(ace['AceFlags'])
                attributes['accessmask'] = ace['Ace']['Mask']['Mask']
                attributes['activedirectoryrights'] = fmt.format_ace_access_mask(ace['Ace']['Mask']['Mask'])
                attributes['isinherited'] = bool(ace['AceFlags'] & 0x10)
                attributes['securityidentifier'] = format_sid(ace['Ace']['Sid'].getData())
                if resolve_sids:
                    converted_sid = attributes['securityidentifier']
                    attributes['securityidentifier'] = self._resolve_sid(converted_sid, sid_mapping)
                try:
                    attributes['objectaceflags'] = fmt.format_object_ace_flags(ace['Ace']['Flags'])
                except KeyError:
                    pass
                try:
                    attributes['objectacetype'] = format_uuid_le(ace['Ace']['ObjectType']) if ace['Ace']['ObjectType'] else '{00000000-0000-0000-0000-000000000000}'
                    attributes['objectacetype'] = guid_map[attributes['objectacetype']]
                except KeyError:
                    pass
                try:
                    attributes['inheritedobjectacetype'] = format_uuid_le(ace['Ace']['InheritedObjectType']) if ace['Ace']['InheritedObjectType'] else '{00000000-0000-0000-0000-000000000000}'
                    attributes['inheritedobjectacetype'] = guid_map[attributes['inheritedobjectacetype']]
                except KeyError:
                    pass

                acl.append(adobj.ACE(attributes))

        return acl

    @LDAPRPCRequester._ldap_connection_init
    def get_netuser(self, queried_username=str(), queried_domain=str(),
                    ads_path=str(), admin_count=False, spn=False,
                    unconstrained=False, allow_delegation=False,
                    preauth_notreq=False,
                    custom_filter=str(), attributes=[]):

        if unconstrained:
            custom_filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

        if allow_delegation:
            custom_filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'

        if admin_count:
            custom_filter += '(admincount=1)'
        # LDAP filter from https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
        if preauth_notreq:
            custom_filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
        user_search_filter = '(samAccountType=805306368){}'.format(custom_filter)
        if queried_username:
            user_search_filter += '(samAccountName={})'.format(queried_username)
        elif spn:
            user_search_filter += '(servicePrincipalName=*)'

        user_search_filter = '(&{})'.format(user_search_filter)

        return self._ldap_search(user_search_filter, adobj.User, attributes=attributes)

    @LDAPRPCRequester._ldap_connection_init
    def get_netgroup(self, queried_groupname='*', queried_sid=str(),
                     queried_username=str(), queried_domain=str(),
                     ads_path=str(), admin_count=False, full_data=False,
                     custom_filter=str()):

        # RFC 4515, section 3
        # However if we escape *, we can no longer use wildcard within `--groupname`
        if not '*' in queried_groupname:
            queried_groupname = escape_filter_chars(queried_groupname)
        else:
            self._logger.warning('"*" detected in "{}", if it also contains "(",")" or "\\", '
                                 'script will probably crash ("invalid filter"). '
                                 'Don\'t use wildcard with these characters'.format(queried_groupname))

        if queried_username:
            self._logger.debug('Queried username = {}'.format(queried_username))
            results = list()
            sam_account_name_to_resolve = [queried_username]
            first_run = True
            while sam_account_name_to_resolve:
                sam_account_name = escape_filter_chars(sam_account_name_to_resolve.pop(0))
                if first_run:
                    first_run = False
                    if admin_count:
                        custom_filter = '(&{}(admincount=1))'.format(custom_filter)
                    objects = self.get_adobject(queried_sam_account_name=sam_account_name,
                                                queried_domain=queried_domain,
                                                ads_path=ads_path, custom_filter=custom_filter)
                    objects += self.get_adobject(queried_name=sam_account_name,
                                                 queried_domain=queried_domain,
                                                 ads_path=ads_path, custom_filter=custom_filter)
                else:
                    objects = self.get_adobject(queried_sam_account_name=sam_account_name,
                                                queried_domain=queried_domain)
                    objects += self.get_adobject(queried_name=sam_account_name,
                                                 queried_domain=queried_domain)

                for obj in objects:
                    try:
                        if not isinstance(obj.memberof, list):
                            obj.memberof = [obj.memberof]
                    except AttributeError:
                        continue
                    for group_dn in obj.memberof:
                        group_sam_account_name = group_dn.split(',')[0].split('=')[1]
                        if not group_sam_account_name in results:
                            results.append(group_sam_account_name)
                            sam_account_name_to_resolve.append(group_sam_account_name)
            final_results = list()
            for group_sam_account_name in results:
                obj_member_of = adobj.Group(list())
                obj_member_of._attributes_dict['samaccountname'] = group_sam_account_name
                final_results.append(obj_member_of)
            return final_results
        else:
            if admin_count:
                custom_filter += '(admincount=1)'

            group_search_filter = custom_filter
            group_search_filter += '(objectCategory=group)'

            if queried_sid:
                self._logger.debug('Queried SID = {}'.format(queried_username))
                group_search_filter += '(objectSid={})'.format(queried_sid)
            elif queried_groupname:
                self._logger.debug('Queried groupname = {}'.format(queried_groupname))
                group_search_filter += '(name={})'.format(queried_groupname)

            if full_data:
                attributes=list()
            else:
                attributes=['samaccountname']

            group_search_filter = '(&{})'.format(group_search_filter)
            return self._ldap_search(group_search_filter, adobj.Group, attributes=attributes)

    @LDAPRPCRequester._ldap_connection_init
    def get_netcomputer(self, queried_computername=str(), queried_spn=str(),
                        queried_os=str(), queried_sp=str(), queried_domain=str(), ads_path=str(), 
                        printers=False, unconstrained=False, laps_passwords=False, pre_created=False,
                        ping=False, full_data=False, custom_filter=str(), attributes=[]):

        if unconstrained:
            custom_filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

        if printers:
            custom_filter += '(objectCategory=printQueue)'

        if laps_passwords:
            custom_filter += '(ms-mcs-AdmPwd=*)'

        if pre_created:
            custom_filter += '(userAccountControl:1.2.840.113556.1.4.803:=4128)'

        computer_search_filter = '(samAccountType=805306369){}'.format(custom_filter)
        for (attr_desc, attr_value) in (('servicePrincipalName', queried_spn),
                ('operatingSystem', queried_os), ('operatingsystemservicepack', queried_sp),
                ('dnsHostName', queried_computername)):
            if attr_value:
                computer_search_filter += '({}={})'.format(attr_desc, attr_value)

        if full_data:
            attributes=list()
        else:
            if not attributes:
                attributes=['samaccountname', 'dnsHostName']
            if laps_passwords:
                attributes.append('ms-mcs-AdmPwd')

        computer_search_filter = '(&{})'.format(computer_search_filter)

        return self._ldap_search(computer_search_filter, adobj.Computer, attributes=attributes)

    @LDAPRPCRequester._ldap_connection_init
    def get_netdomaincontroller(self, queried_domain=str()):

        domain_controller_filter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

        return self.get_netcomputer(queried_domain=queried_domain, full_data=True,
                                    custom_filter=domain_controller_filter)

    @LDAPRPCRequester._ldap_connection_init
    def get_netfileserver(self, queried_domain=str(), target_users=list()):

        def split_path(path):
            split_path = path.split('\\')
            if len(split_path) >= 3:
                return split_path[2]

        file_server_attributes = ['homedirectory', 'scriptpath', 'profilepath']
        results = set()
        if target_users:
            users = list()
            for target_user in target_users:
                users += self.get_netuser(target_user, queried_domain,
                        attributes=file_server_attributes)
        else:
            users = self.get_netuser(queried_domain=queried_domain,
                    attributes=file_server_attributes)

        for user in users:
            for full_path in (user.homedirectory, user.scriptpath, user.profilepath):
                if not full_path:
                    continue
                path = split_path(full_path)
                if path:
                    results.add(path)

        final_results = list()
        for file_server_name in results:
            attributes = dict()
            attributes['dnshostname'] = file_server_name
            final_results.append(adobj.FileServer(attributes))

        return final_results

    @LDAPRPCRequester._ldap_connection_init
    def get_dfsshare(self, version=['v1', 'v2'], queried_domain=str(), ads_path=str()):

        def _get_dfssharev1():
            dfs_search_filter = '(objectClass=fTDfs)'

            intermediate_results = self._ldap_search(dfs_search_filter, adobj.ADObject,
                                                attributes=['remoteservername', 'name'])
            results = list()
            for dfs in intermediate_results:
                for remote_server in dfs.remoteservername:
                    remote_server = str(remote_server)
                    if '\\' in remote_server:
                        attributes = {'name': dfs.name,
                                'remoteservername': remote_server.split('\\')[2]}
                        results.append(adobj.DFS(attributes))

            return results

        def _get_dfssharev2():
            dfs_search_filter = '(objectClass=msDFS-Linkv2)'

            intermediate_results = self._ldap_search(dfs_search_filter, adobj.ADObject,
                                                attributes=['msdfs-linkpathv2','msDFS-TargetListv2'])
            results = list()
            for dfs in intermediate_results:
                attributes = list()

                share_name = getattr(dfs, 'msdfs-linkpathv2')

                xml_target_list = getattr(dfs, 'msdfs-targetlistv2')[2:].decode('utf-16le')
                soup_target_list = BeautifulSoup(xml_target_list, 'xml')
                for target in soup_target_list.targets.contents:
                    if '\\' in target.string:
                        server_name, dfs_root = target.string.split('\\')[2:4]
                        attributes = {'name': '{}{}'.format(dfs_root, share_name),
                                'remoteservername': server_name}

                results.append(adobj.DFS(attributes))

            return results

        version_to_function = {'v1': _get_dfssharev1, 'v2': _get_dfssharev2}
        results = list()

        for v in version:
            results += version_to_function[v]()

        return results

    @LDAPRPCRequester._ldap_connection_init
    def get_netou(self, queried_domain=str(), queried_ouname='*',
                  queried_guid=str(), ads_path=str(), full_data=False):

        ou_search_filter = '(objectCategory=organizationalUnit)'

        if queried_ouname:
            ou_search_filter += '(name={})'.format(queried_ouname)

        if queried_guid:
            ou_search_filter += '(gplink=*{}*)'.format(queried_guid)

        if full_data:
            attributes = list()
        else:
            attributes = ['distinguishedName']

        ou_search_filter = '(&{})'.format(ou_search_filter)

        return self._ldap_search(ou_search_filter, adobj.OU, attributes=attributes)

    @LDAPRPCRequester._ldap_connection_init
    def get_netsite(self, queried_domain=str(), queried_sitename=str(),
                    queried_guid=str(), ads_path=str(), ads_prefix=str(),
                    full_data=False):

        site_search_filter = '(objectCategory=site)'

        if queried_sitename:
            site_search_filter += '(name={})'.format(queried_sitename)

        if queried_guid:
            site_search_filter += '(gplink=*{}*)'.format(queried_guid)

        if full_data:
            attributes = list()
        else:
            attributes = ['name']

        site_search_filter = '(&{})'.format(site_search_filter)

        return self._ldap_search(site_search_filter, adobj.Site, attributes=attributes)

    @LDAPRPCRequester._ldap_connection_init
    def get_netsubnet(self, queried_domain=str(), queried_sitename=str(),
                      ads_path=str(), ads_prefix=str(), full_data=False):

        subnet_search_filter = '(objectCategory=subnet)'

        if queried_sitename:
            if not queried_sitename.endswith('*'):
                queried_sitename += '*'
            subnet_search_filter += '(siteobject=*CN={})'.format(queried_sitename)

        if full_data:
            attributes = list()
        else:
            attributes = ['name', 'siteobject']

        subnet_search_filter = '(&{})'.format(subnet_search_filter)

        return self._ldap_search(subnet_search_filter, adobj.Subnet, attributes=attributes)

    @LDAPRPCRequester._ldap_connection_init
    def get_netgroupmember(self, queried_groupname=str(), queried_sid=str(),
                           queried_domain=str(), ads_path=str(), recurse=False,
                           use_matching_rule=False, full_data=False,
                           custom_filter=str()):

        def _get_members(_groupname=str(), _sid=str()):
            try:
                # `--groupname` option is supplied
                if _groupname:
                    self._logger.debug('Queried groupname = {}'.format(queried_groupname))
                    groups = self.get_netgroup(queried_groupname=_groupname,
                                               queried_domain=self._queried_domain,
                                               full_data=True)

                # `--groupname` option is missing, falling back to the "Domain Admins"
                else:
                    self._logger.debug('No groupname provided, falling back to the "Domain Admins"'.format(queried_groupname))
                    if _sid:
                        queried_sid = _sid
                    else:
                        # Logic extract from pywerview.functions.Misc get_domainsid to save object creation
                        # LDAP filter to extract DC
                        domain_controller_filter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
                        domain_controllers = self.get_netcomputer(queried_domain=queried_domain, custom_filter=domain_controller_filter,
                                                                attributes=['objectsid'])
                        if domain_controllers:
                            primary_dc = domain_controllers[0]
                            domain_sid = primary_dc.objectsid

                            # we need to retrieve the domain sid from the controller sid
                            domain_sid = '-'.join(domain_sid.split('-')[:-1])
                            queried_sid = domain_sid + '-512'
                            self._logger.debug('Found Domains Admins SID = {}'.format(queried_sid))
                        else:
                            self._logger.critical('We did not manage to retrieve domain controller, please specify a group name')
                            return list()

                    groups = self.get_netgroup(queried_sid=queried_sid,
                                               queried_domain=self._queried_domain,
                                               full_data=True)
            except IndexError:
                raise ValueError('The group {} was not found'.format(_groupname))

            final_members = list()

            for group in groups:
                members = list()
                if recurse and use_matching_rule:
                    group_memberof_filter = '(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={}){})'.format(group.distinguishedname, custom_filter)

                    members = self.get_netuser(custom_filter=group_memberof_filter,
                                               queried_domain=self._queried_domain)
                else:
                    # TODO: range cycling
                    try:
                        for member in group.member:
                            # RFC 4515, section 3
                            self._logger.warning('Member name = "{}" will be escaped'.format(member))
                            member = escape_filter_chars(member, encoding='utf-8')
                            dn_filter = '(distinguishedname={}){}'.format(member, custom_filter)
                            members += self.get_adobject(custom_filter=dn_filter, queried_domain=self._queried_domain)
                    # The group doesn't have any members
                    except AttributeError:
                        self._logger.debug('The group doesn\'t have any members')
                        continue

                for member in members:
                    if full_data:
                        final_member = member
                    else:
                        final_member = adobj.ADObject(list())

                    member_dn = member.distinguishedname
                    try:
                        member_domain = member_dn[member_dn.index('DC='):].replace('DC=', '').replace(',', '.')
                    except IndexError:
                        self._logger.warning('Exception was raised while handling member_dn, falling back to empty string')
                        member_domain = str()

                    # https://serverfault.com/questions/788888/what-does-an-alias-group-means-in-sid-context
                    is_group = (member.samaccounttype == 'GROUP_OBJECT') or (member.samaccounttype == 'ALIAS_OBJECT')

                    attributes = dict()
                    if queried_domain:
                        attributes['groupdomain'] = queried_domain
                    else:
                        attributes['groupdomain'] = self._queried_domain
                    attributes['groupname'] = group.name
                    attributes['membername'] = member.samaccountname
                    attributes['memberdomain'] = member_domain
                    if is_group:
                        attributes['useraccountcontrol'] = str()
                        self._logger.debug('{0} is a {1}, ignoring the useraccountcontrol'.format(member.samaccountname, member.samaccounttype))
                    else:
                        attributes['useraccountcontrol'] = member.useraccountcontrol
                    attributes['isgroup'] = is_group
                    attributes['memberdn'] = member_dn
                    attributes['objectsid'] = member.objectsid

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

    @LDAPRPCRequester._ldap_connection_init
    def get_netdomaintrust(self, queried_domain, full_data=False):

        if full_data:
            attributes=list()
        else:
            attributes=['trustpartner', 'trustdirection', 'whencreated', 'whenchanged',
                        'trusttype', 'trustattributes', 'securityidentifier']

        trust_search_filter = '(&(objectClass=trustedDomain))'

        return self._ldap_search(trust_search_filter, adobj.Trust, attributes=attributes)

    @LDAPRPCRequester._rpc_connection_init(r'\srvsvc')
    def get_netsession(self):

        try:
            resp = srvs.hNetrSessionEnum(self._rpc_connection, '\x00', NULL, 10)
        except DCERPCException:
            return list()

        results = list()
        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            results.append(rpcobj.Session(session))

        return results

    @LDAPRPCRequester._rpc_connection_init(r'\srvsvc')
    def get_netshare(self):

        resp = srvs.hNetrShareEnum(self._rpc_connection, 1)

        results = list()
        for share in resp['InfoStruct']['ShareInfo']['Level1']['Buffer']:
            results.append(rpcobj.Share(share))

        return results

    @LDAPRPCRequester._rpc_connection_init(r'\srvsvc')
    def get_localdisks(self):

        resp = srvs.hNetrServerDiskEnum(self._rpc_connection, 0)

        results = list()
        for disk in resp['DiskInfoStruct']['Buffer']:
            if disk['Disk'] != '\x00':
                results.append(rpcobj.Disk(disk))

        return results

    @LDAPRPCRequester._rpc_connection_init(r'\samr')
    def get_netdomain(self):

        resp = samr.hSamrConnect(self._rpc_connection)
        server_handle = resp['ServerHandle']

        # We first list every domain in the SAM
        resp = samr.hSamrEnumerateDomainsInSamServer(self._rpc_connection, server_handle)

        results = list()
        for domain in resp['Buffer']['Buffer']:
            results.append(domain['Name'])

        return results

    @LDAPRPCRequester._rpc_connection_init(r'\wkssvc')
    def get_netloggedon(self):

        try:
            resp = wkst.hNetrWkstaUserEnum(self._rpc_connection, 1)
        except DCERPCException:
            return list()

        results = list()
        for wksta_user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            results.append(rpcobj.WkstaUser(wksta_user))

        return results

    # TODO: if self._target_computer == self._domain_controller, check that
    # self._domain_controller is indeed a domain controller
    @LDAPRPCRequester._ldap_connection_init
    @LDAPRPCRequester._rpc_connection_init(r'\samr')
    def get_netlocalgroup(self, queried_groupname=str(), list_groups=False,
                          recurse=False):
        from impacket.nt_errors import STATUS_MORE_ENTRIES
        results = list()

        resp = samr.hSamrConnect(self._rpc_connection)
        server_handle = resp['ServerHandle']

        # We first list every domain in the SAM
        resp = samr.hSamrEnumerateDomainsInSamServer(self._rpc_connection, server_handle)
        domains = resp['Buffer']['Buffer']
        domain_handles = dict()
        for local_domain in domains:
            resp = samr.hSamrLookupDomainInSamServer(self._rpc_connection, server_handle, local_domain['Name'])
            domain_sid = 'S-1-5-{}'.format('-'.join(str(x) for x in resp['DomainId']['SubAuthority']))
            resp = samr.hSamrOpenDomain(self._rpc_connection, serverHandle=server_handle, domainId=resp['DomainId'])
            domain_handles[domain_sid] = resp['DomainHandle']

        # If we list the groups
        if list_groups:
            # We browse every domain
            for domain_sid, domain_handle in domain_handles.items():
                # We enumerate local groups in every domain
                enumeration_context = 0
                groups = list()
                while True:
                    resp = samr.hSamrEnumerateAliasesInDomain(self._rpc_connection, domain_handle,
                            enumerationContext=enumeration_context)
                    groups += resp['Buffer']['Buffer']

                    enumeration_context = resp['EnumerationContext']
                    if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                        break

                # We get information on every group
                for group in groups:
                    resp = samr.hSamrRidToSid(self._rpc_connection, domain_handle, rid=group['RelativeId'])
                    sid = 'S-1-5-{}'.format('-'.join(str(x) for x in resp['Sid']['SubAuthority']))

                    resp = samr.hSamrOpenAlias(self._rpc_connection, domain_handle, aliasId=group['RelativeId'])
                    alias_handle = resp['AliasHandle']
                    resp = samr.hSamrQueryInformationAlias(self._rpc_connection, alias_handle)

                    final_group = rpcobj.Group(resp['Buffer']['General'])
                    final_group.add_attributes({'server': self._target_computer, 'sid': sid})

                    results.append(final_group)

                    samr.hSamrCloseHandle(self._rpc_connection, alias_handle)

                samr.hSamrCloseHandle(self._rpc_connection, domain_handle)
        # If we query a group
        else:
            queried_group_rid = None
            queried_group_domain_handle = None

            # If the user is looking for a particular group
            if queried_groupname:
                # We look for it in every domain
                for _, domain_handle in domain_handles.items():
                    try:
                        resp = samr.hSamrLookupNamesInDomain(self._rpc_connection, domain_handle, [queried_groupname])
                        queried_group_rid = resp['RelativeIds']['Element'][0]['Data']
                        queried_group_domain_handle = domain_handle
                        break
                    except (DCERPCSessionError, KeyError, IndexError):
                        continue
                else:
                    raise ValueError('The group \'{}\' was not found on the target server'.format(queried_groupname))
            # Otherwise, we look for the local Administrators group
            else:
                queried_group_rid = 544
                resp = samr.hSamrLookupDomainInSamServer(self._rpc_connection, server_handle, 'BUILTIN')
                resp = samr.hSamrOpenDomain(self._rpc_connection, serverHandle=server_handle, domainId=resp['DomainId'])
                queried_group_domain_handle = resp['DomainHandle']

            # We get a handle on the group, and list its members
            try:
                group = samr.hSamrOpenAlias(self._rpc_connection, queried_group_domain_handle, aliasId=queried_group_rid)
                resp = samr.hSamrGetMembersInAlias(self._rpc_connection, group['AliasHandle'])
            except DCERPCSessionError:
                raise ValueError('The name \'{}\' is not a valid group on the target server'.format(queried_groupname))

            # For every user, we look for information in every local domain
            for member in resp['Members']['Sids']:
                attributes = dict()
                member_rid = member['SidPointer']['SubAuthority'][-1]
                member_sid = 'S-1-5-{}'.format('-'.join(str(x) for x in member['SidPointer']['SubAuthority']))

                attributes['server'] = self._target_computer
                attributes['sid'] = member_sid

                for domain_sid, domain_handle in domain_handles.items():
                    # We've found a local member
                    if member_sid.startswith(domain_sid):
                        attributes['isdomain'] = False
                        resp = samr.hSamrQueryInformationDomain(self._rpc_connection, domain_handle)
                        member_domain = resp['Buffer']['General2']['I1']['DomainName']
                        try:
                            resp = samr.hSamrOpenUser(self._rpc_connection, domain_handle, userId=member_rid)
                            member_handle = resp['UserHandle']
                            attributes['isgroup'] = False
                            resp = samr.hSamrQueryInformationUser(self._rpc_connection, member_handle)
                            attributes['name'] = '{}\\{}'.format(member_domain, resp['Buffer']['General']['UserName'])
                        except DCERPCSessionError:
                            resp = samr.hSamrOpenAlias(self._rpc_connection, domain_handle, aliasId=member_rid)
                            member_handle = resp['AliasHandle']
                            attributes['isgroup'] = True
                            resp = samr.hSamrQueryInformationAlias(self._rpc_connection, member_handle)
                            attributes['name'] = '{}\\{}'.format(member_domain, resp['Buffer']['General']['Name'])
                        attributes['lastlogon'] = str()
                        break
                # It's a domain member
                else:
                    attributes['isdomain'] = True
                    if self._ldap_connection is not None:
                        try:
                            ad_object = self.get_adobject(queried_sid=member_sid)[0]
                            member_dn = ad_object.distinguishedname
                            member_domain = member_dn[member_dn.index('DC='):].replace('DC=', '').replace(',', '.')
                            try:
                                attributes['name'] = '{}\\{}'.format(member_domain, ad_object.samaccountname)
                            except AttributeError:
                                # Here, the member is a foreign security principal
                                # TODO: resolve it properly
                                self._logger.warning('The member is a foreign security principal, SID will not be resolved')
                                attributes['name'] = '{}\\{}'.format(member_domain, ad_object.objectsid)
                            attributes['isgroup'] = 'group' in ad_object.objectclass
                            try:
                                attributes['lastlogon'] = ad_object.lastlogon
                            except AttributeError:
                                self._logger.warning('lastlogon is not set, falling back to empty string')
                                attributes['lastlogon'] = str()
                        except IndexError:
                            # We did not manage to resolve this SID against the DC
                            self._logger.warning('We did not manage to resolve this SID ({}) against the DC'.format(member_sid))
                            attributes['isdomain'] = False
                            attributes['isgroup'] = False
                            attributes['name'] = attributes['sid']
                            attributes['lastlogon'] = str()
                    else:
                        attributes['isgroup'] = False
                        attributes['name'] = str()
                        attributes['lastlogon'] = str()

                results.append(rpcobj.RPCObject(attributes))

                # If we recurse and the member is a domain group, we query every member
                # TODO: implement check on self._domain_controller here?
                if self._ldap_connection and self._domain_controller and recurse and attributes['isdomain'] and attributes['isgroup']:
                    for domain_member in self.get_netgroupmember(full_data=True, recurse=True, queried_sid=attributes['sid']):
                        domain_member_attributes = dict()
                        domain_member_attributes['isdomain'] = True
                        member_dn = domain_member.distinguishedname
                        member_domain = member_dn[member_dn.index('DC='):].replace('DC=', '').replace(',', '.')
                        domain_member_attributes['name'] = '{}\\{}'.format(member_domain, domain_member.samaccountname)
                        domain_member_attributes['isgroup'] = domain_member.isgroup
                        domain_member_attributes['isdomain'] = True
                        # TODO: Nope, maybe here we can call get-netdomaincontroller ?
                        # Need to check in powerview
                        domain_member_attributes['server'] = attributes['name']
                        domain_member_attributes['sid'] = domain_member.objectsid
                        try:
                            domain_member_attributes['lastlogin'] = ad_object.lastlogon
                        except AttributeError:
                            self._logger.warning('lastlogon is not set, falling back to empty string')
                            domain_member_attributes['lastlogin'] = str()
                        results.append(rpcobj.RPCObject(domain_member_attributes))

        return results

    @LDAPRPCRequester._wmi_connection_init()
    def get_netprocess(self):
        wmi_enum_process = self._wmi_connection.ExecQuery('SELECT * from Win32_Process',
                                                          lFlags=WBEM_FLAG_FORWARD_ONLY)
        while True:
            try:
                # TODO: do we have to get them one by one?
                wmi_process = wmi_enum_process.Next(0xffffffff, 1)[0]
                wmi_process_owner = wmi_process.GetOwner()

                # Sometimes GetOwner() returns None but the list is not over
                if wmi_process_owner != None:
                    attributes = {'computername': self._target_computer,
                                  'processname': wmi_process.Name,
                                  'processid': wmi_process.ProcessId,
                                  'user': wmi_process_owner.User,
                                  'domain': wmi_process_owner.Domain}

                    result_process = rpcobj.Process(attributes)
                    yield result_process
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

    @LDAPRPCRequester._wmi_connection_init()
    def get_userevent(self, event_type=['logon', 'tgt'], date_start=5):
        limit_date = (datetime.today() - timedelta(days=date_start)).strftime('%Y%m%d%H%M%S.%f-000')
        if event_type == ['logon']:
            where_clause = 'EventCode=4624'
        elif event_type == ['tgt']:
            where_clause = 'EventCode=4768'
        else:
            where_clause = '(EventCode=4624 OR EventCode=4768)'

        wmi_enum_event = self._wmi_connection.ExecQuery('SELECT * from Win32_NTLogEvent where {}'\
                                                        'and TimeGenerated >= \'{}\''.format(where_clause, limit_date),
                                                        lFlags=WBEM_FLAG_FORWARD_ONLY)
        while True:
            try:
                # TODO: do we have to get them one by one?
                wmi_event = wmi_enum_event.Next(0xffffffff, 1)[0]
                wmi_event_type = wmi_event.EventIdentifier
                wmi_event_info = wmi_event.InsertionStrings
                time = datetime.strptime(wmi_event.TimeGenerated, '%Y%m%d%H%M%S.%f-000')
                if wmi_event_type == 4624:
                    logon_type = int(wmi_event_info[8])
                    user = wmi_event_info[5]
                    domain = wmi_event_info[6]
                    address = wmi_event_info[18]
                    if logon_type not in [2, 3] or user.endswith('$') \
                       or (user.lower == 'anonymous logon'):
                        continue
                else:
                    logon_type = str()
                    user = wmi_event_info[0]
                    domain = wmi_event_info[1]
                    address = wmi_event_info[9].replace('::ffff:', '')

                attributes = {'computername': self._target_computer,
                              'logontype': logon_type,
                              'username': user,
                              'domain': domain,
                              'address': address,
                              'time': time,
                              'id': wmi_event_type}
                result_event = rpcobj.Event(attributes)
                yield result_event
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

