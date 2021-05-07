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

from datetime import datetime, timedelta
import inspect
import struct
import pyasn1
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR

import pywerview.functions.misc as misc

class ADObject:
    __uac_flags = {0x0000001: 'SCRIPT',
                   0x0000002: 'ACCOUNTDISABLE',
                   0x0000008: 'HOMEDIR_REQUIRED',
                   0x0000010: 'LOCKOUT',
                   0x0000020: 'PASSWD_NOTREQD',
                   0x0000040: 'PASSWD_CANT_CHANGE',
                   0x0000080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
                   0x0000100: 'TEMP_DUPLICATE_ACCOUNT',
                   0x0000200: 'NORMAL_ACCOUNT',
                   0x0000800: 'INTERDOMAIN_TRUST_ACCOUNT',
                   0x0001000: 'WORKSTATION_TRUST_ACCOUNT',
                   0x0002000: 'SERVER_TRUST_ACCOUNT',
                   0x0010000: 'DONT_EXPIRE_PASSWORD',
                   0x0020000: 'MNS_LOGON_ACCOUNT',
                   0x0040000: 'SMARTCARD_REQUIRED',
                   0x0080000: 'TRUSTED_FOR_DELEGATION',
                   0x0100000: 'NOT_DELEGATED',
                   0x0200000: 'USE_DES_KEY_ONLY',
                   0x0400000: 'DONT_REQ_PREAUTH',
                   0x0800000: 'PASSWORD_EXPIRED',
                   0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
                   0x4000000: 'PARTIAL_SECRETS_ACCOUNT'}

    _well_known_sids = {'S-1-0-0': b'Nobody', 'S-1-0': b'Null Authority', 'S-1-1-0': b'Everyone',
                        'S-1-1': b'World Authority', 'S-1-2-0': b'Local', 'S-1-2-1': b'Console Logon',
                        'S-1-2': b'Local Authority', 'S-1-3-0': b'Creator Owner', 'S-1-3-1': b'Creator Group',
                        'S-1-3-2': b'Creator Owner Server', 'S-1-3-3': b'Creator Group Server', 'S-1-3-4': b'Owner Rights',
                        'S-1-3': b'Creator Authority', 'S-1-4': b'Non-unique Authority', 'S-1-5-10': b'Principal Self',
                        'S-1-5-11': b'Authenticated Users', 'S-1-5-12': b'Restricted Code', 'S-1-5-13': b'Terminal Server Users',
                        'S-1-5-14': b'Remote Interactive Logon', 'S-1-5-17': b'This Organization', 'S-1-5-18': b'Local System',
                        'S-1-5-19': b'NT Authority', 'S-1-5-1': b'Dialup', 'S-1-5-20': b'NT Authority',
                        'S-1-5-2': b'Network', 'S-1-5-32-546': b'Guests', 'S-1-5-32-547': b'Power Users',
                        'S-1-5-32-551': b'Backup Operators', 'S-1-5-32-555': b'Builtin\\Remote Desktop Users',
                        'S-1-5-32-556': b'Builtin\\Network Configuration Operators',
                        'S-1-5-32-557': b'Builtin\\Incoming Forest Trust Builders',
                        'S-1-5-32-558': b'Builtin\\Performance Monitor Users',
                        'S-1-5-32-559': b'Builtin\\Performance Log Users',
                        'S-1-5-32-560': b'Builtin\\Windows Authorization Access Group',
                        'S-1-5-32-561': b'Builtin\\Terminal Server License Servers',
                        'S-1-5-32-562': b'Builtin\\Distributed COM Users',
                        'S-1-5-32-569': b'Builtin\\Cryptographic Operators',
                        'S-1-5-32-573': b'Builtin\\Event Log Readers',
                        'S-1-5-32-574': b'Builtin\\Certificate Service DCOM Access',
                        'S-1-5-32-575': b'Builtin\\RDS Remote Access Servers',
                        'S-1-5-32-576': b'Builtin\\RDS Endpoint Servers',
                        'S-1-5-32-577': b'Builtin\\RDS Management Servers',
                        'S-1-5-32-578': b'Builtin\\Hyper-V Administrators',
                        'S-1-5-32-579': b'Builtin\\Access Control Assistance Operators',
                        'S-1-5-32-580': b'Builtin\\Remote Management Users',
                        'S-1-5-32-582': b'Storage Replica Administrators',
                        'S-1-5-3': b'Batch', 'S-1-5-4': b'Interactive', 'S-1-5-64-10': b'NTLM Authentication',
                        'S-1-5-64-14': b'SChannel Authentication', 'S-1-5-64-21': b'Digest Authentication',
                        'S-1-5-6': b'Service', 'S-1-5-7': b'Anonymous', 'S-1-5-80-0': b'NT Services\\All Services',
                        'S-1-5-80': b'NT Service', 'S-1-5-8': b'Proxy', 'S-1-5-9': b'Enterprise Domain Controllers',
                        'S-1-5': b'NT Authority'}



    def __init__(self, attributes):
        self.add_attributes(attributes)

    def add_attributes(self, attributes):
        for attr in attributes:
            t = str(attr).lower()
            if len(attributes[attr]) > 1 :
                setattr(self, t, attributes[attr])
            else:
                try:
                    setattr(self, t, attributes[attr][0])
                # the server returns the attribute name but attribute value is empty
                except IndexError:
                    setattr(self, t, '')

    # In this method, we try to pretty print common AD attributes
    def __str__(self):
        s = str()
        members = inspect.getmembers(self, lambda x: not(inspect.isroutine(x)))
        max_length = 0
        for member in members:
            if not member[0].startswith('_'):
                if len(member[0]) > max_length:
                    max_length = len(member[0])
        for member in members:
            if not member[0].startswith('_'):
                #print(len(member[1]))
               # print(member)
                # ??
                if member[0] in ('logonhours', 'msds-generationid'):        
                    value = member[1]
                    member_value = [x for x in value]

                # Attribute is a SID
                elif member[0] in ('objectsid', 'ms-ds-creatorsid', 'securityidentifier'):
                    init_value = member[1]
                    member_value = misc.Utils.convert_sidtostr(init_value)
 
                # Attribute is a GUID
                elif member[0] == 'objectguid':
                    init_value = member[1]
                    member_value = misc.Utils.convert_guidtostr(init_value)

                # Attribute is a datetime (or a list of datetime)
                elif member[0] in ('dscorepropagationdata', 'whenchanged', 'whencreated','msexchwhenmailboxcreated'):
                    member_value_temp = list()

                    if isinstance(member[1], list):
                        for val in member[1]:
                            member_value_temp.append(str(datetime.strptime(str(val.decode('utf-8')), '%Y%m%d%H%M%S.0Z')))
                    else:
                        member_value_temp.append(str(datetime.strptime(str(member[1].decode('utf-8')), '%Y%m%d%H%M%S.0Z')))
                    member_value = (',\n' + ' ' * (max_length + 2)).join(str(x) for x in member_value_temp)
                
                # Attribute is a timestamp
                elif member[0] in ('accountexpires', 'pwdlastset', 'badpasswordtime', 'lastlogontimestamp', 'lastlogon', 'lastlogoff'):
                    if int(member[1].decode('utf-8')) != 9223372036854775807:
                        timestamp = (int(member[1].decode('utf-8')) - 116444736000000000)/10000000
                        member_value = datetime.fromtimestamp(0) + timedelta(seconds=timestamp)
                    else:
                        member_value = 'never'

                elif member[0] in ('msds-lockoutduration', 'msds-lockoutobservationwindow', 'msds-maximumpasswordage', 'msds-minimumpasswordage'):
                    member_value = timedelta(microseconds=abs(int(member[1]))/10)
                
                # The object is a group
                elif member[0] == 'objectclass':
                    member_value = [x.decode('utf-8') for x in member[1]]
                    # TODO: We must not setettr in a __str__ method
                    # I comment this until it breaks something
                    # setattr(self, 'isgroup', ('group' in member_value))
                elif member[0] == 'isgroup':
                    member_value = member[1]

                # We pretty print useraccountcontrol
                elif member[0] == 'useraccountcontrol':
                    member_value = list()
                    for uac_flag, uac_label in ADObject.__uac_flags.items():
                        if int(member[1]) & uac_flag == uac_flag:
                            member_value.append(uac_label)

                # Attribute is a list of value
                elif isinstance(member[1], list):
                    # Value is a list of string
                    try:
                        member_value_temp = [x.decode('utf-8') for x in member[1]]
                        member_value = (',\n' + ' ' * (max_length + 2)).join(str(x) for x in member_value_temp)
                    # Value is a list of bytearray
                    except (UnicodeDecodeError):
                        member_value_temp = [x for x in member[1]]
                        member_value = (',\n' + ' ' * (max_length + 2)).join(x.hex()[:100] + '...' for x in member_value_temp)
                    # Value is a list, but idk
                    except (AttributeError):
                        member_value = member[1]

                # Default case, attribute seems to be a simple string
                else:
                    # Value is a string
                    try:
                        member_value = member[1].decode('utf-8')
                    # Value is a bytearray
                    except (UnicodeError):
                        member_value = '{}...'.format(member[1].hex()[:100])
                    # Attribut exists but it is empty
                    # add some info to help debugging
                    except (AttributeError, IndexError):
                        member_value = '*empty attribute or internal error*'

                s += '{}: {}{}\n'.format(member[0], ' ' * (max_length - len(member[0])), member_value)

        s = s[:-1]
        return s
             
    def __repr__(self):
        return str(self)

class ACE(ADObject):
    __ace_flags = {0x1: 'object_inherit', 0x2: 'container_inherit',
                   0x4: 'non_propagate_inherit', 0x8: 'inherit_only',
                   0x10: 'inherited_ace', 0x20: 'audit_successful_accesses',
                   0x40: 'audit_failed_access'}

    __object_ace_flags = {0x1: 'object_ace_type_present', 0x2: 'inherited_object_ace_type_present'}

    # Resources: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
    __access_mask = {0x1: 'create_child', 0x2: 'delete_child',
                     0x4: 'list_children', 0x08: 'self',
                     0x10: 'read_property', 0x20: 'write_property',
                     0x40: 'delete_tree', 0x80: 'list_object',
                     0x100: 'extended_right', 0x10000: 'delete',
                     0x20000: 'read_control', 0x40000: 'write_dacl',
                     0x80000: 'write_owner'}

    __access_mask_generic = {0xf01ff: 'generic_all', 0x20094: 'generic_read',
                             0x20028: 'generic_write', 0x20004: 'generic_execute'}

    def __init__(self, attributes):
        ADObject.__init__(self, attributes)

        # We set the activedirectoryrights attribute, which is just pretty
        # printing of the access mask
        activedirectoryrights = list()
        access_mask_temp = self.accessmask
        # We first check if any generic mask matches, and remove the flags if so
        for mask, mask_label in ACE.__access_mask_generic.items():
            if (access_mask_temp & mask) == mask:
                activedirectoryrights.append(mask_label)
                access_mask_temp ^= mask
        # We check the remaining flags
        for mask, mask_label in ACE.__access_mask.items():
            if (access_mask_temp & mask) == mask:
                activedirectoryrights.append(mask_label)

        self.activedirectoryrights = activedirectoryrights

        # We set iscallback, depending on the type of ACE
        setattr(self, 'iscallback', (b'CALLBACK' in self.acetype))

    def __str__(self):
        s = str()

        members = inspect.getmembers(self, lambda x: not(inspect.isroutine(x)))
        max_length = len('inheritedobjectacetype')

        for member in members:
            if member[0].startswith('_'):
                continue
            elif member[0] in ('objectsid', 'securityidentifier'):
                init_value = member[1]
                if init_value.startswith(b'\x01'):
                    member_value = misc.Utils.convert_sidtostr(init_value)
                else:
                    member_value = init_value.decode('utf8')
            elif member[0] in ('objectacetype', 'inheritedobjectacetype'):
                init_value = member[1]
                try:
                    member_value = misc.Utils.convert_guidtostr(init_value)
                except (TypeError, struct.error):
                    member_value = init_value
            elif member[0] == 'accessmask':
                member_value = member[1]
            elif member[0].endswith('flags'):
                if member[0] == 'aceflags':
                    flags = ACE.__ace_flags
                elif member[0] == 'objectaceflags':
                    flags = ACE.__object_ace_flags
                else:
                    continue
                member_value_temp = list()
                for flag, flag_label in flags.items():
                    if member[1] & flag:
                        member_value_temp.append(flag_label)
                if member_value_temp:
                    member_value = ', '.join(member_value_temp)
                else:
                    member_value = 'None'
            elif type(member[1]) in (int, bool):
                member_value = member[1]
            elif isinstance(member[1], list):
                member_value = ', '.join(member[1])
            else:
                # Value is a string
                try:
                    member_value = member[1].decode('utf-8')
                # Value is a bytearray
                except (UnicodeError):
                    member_value = '{}...'.format(member[1].hex()[:100])
                # Attribut exists but it is empty
                # add some info to help debugging
                except (AttributeError, IndexError):
                    member_value = '*empty attribute or internal error*'
            s += '{}: {}{}\n'.format(member[0], ' ' * (max_length - len(member[0])), member_value)

        return s

class User(ADObject):
    def __init__(self, attributes):
        ADObject.__init__(self, attributes)
        for attr in filter(lambda _: _ in attributes, ('homedirectory',
                                                       'scriptpath',
                                                       'profilepath')):
            if not hasattr(self, attr):
                setattr(self, attr, str())

class Group(ADObject):
    def __init__(self, attributes):
        ADObject.__init__(self, attributes)
        try:
            if not isinstance(self.member, list):
                self.member = [self.member]
        except AttributeError:
            pass

class Computer(ADObject):
    pass

class FileServer(ADObject):
    pass

class DFS(ADObject):
    pass

class OU(ADObject):
    pass

class Site(ADObject):
    pass

class Subnet(ADObject):
    pass

class Trust(ADObject):
    __trust_attrib = {0x1: 'non_transitive', 0x2: 'uplevel_only',
                      0x4: 'filter_sids', 0x8: 'forest_transitive',
                      0x10: 'cross_organization', 0x20: 'within_forest',
                      0x40: 'treat_as_external',
                      0x80: 'trust_uses_rc4_encryption',
                      0x100: 'trust_uses_aes_keys',
                      0X200: 'cross_organization_no_tgt_delegation',
                      0x400: 'pim_trust'}

    __trust_direction = {0: 'disabled', 1: 'inbound',
                         2: 'outbound', 3: 'bidirectional'}

    __trust_type = {1: 'windows_non_active_directory',
                    2: 'windows_active_directory', 3: 'mit'}

    # Pretty printing Trust object, we don't want to print all the attributes
    # so we only print useful ones (trustattributes, trustdirection, trustpartner
    # trusttype, whenchanged, whencreated)
    def __str__(self):
        s = str()

        #Temporary attributes storage
        trust_attributes = list()
        trust_direction = str()

        members = inspect.getmembers(self, lambda x: not(inspect.isroutine(x)))
        max_length = len('trustattributes')

        for member in members:
            if member[0].startswith('_'):
                continue

            elif member[0] == 'trustpartner':
                member_value = member[1].decode('utf-8')

            elif member[0] == 'trustdirection':
                member_value = Trust.__trust_direction.get(int(member[1].decode('utf-8')), 'unknown')
                trust_direction = member_value

            elif member[0] == 'trusttype':
                member_value = Trust.__trust_type.get(int(member[1].decode('utf-8')), 'unknown')
            
            elif member[0] in ('whencreated','whenchanged'):
                member_value = str(datetime.strptime(str(member[1].decode('utf-8')), '%Y%m%d%H%M%S.0Z'))

            elif member[0] == 'trustattributes':
                member_value_temp = list()
                for attrib_flag, attrib_label in Trust.__trust_attrib.items():
                    if int(member[1].decode('utf-8')) & attrib_flag:
                        member_value_temp.append(attrib_label)
                trust_attributes = member_value_temp

                # If the filter SIDs attribute is not manually set, we check if we're
                # not in a use case where SIDs are implicitly filtered
                # Based on https://github.com/vletoux/pingcastle/blob/master/Healthcheck/TrustAnalyzer.cs
                if 'filter_sids' not in trust_attributes:
                    if not (trust_direction == 'disabled' or \
                            trust_direction == 'inbound' or \
                            'within_forest' in trust_attributes or \
                            'pim_trust' in trust_attributes):
                        if 'forest_transitive' in trust_attributes and 'treat_as_external' not in trust_attributes:
                            member_value_temp.append('filter_sids')
                member_value = (',\n' + ' ' * (max_length + 2)).join(str(x) for x in member_value_temp)

            else:
                continue
            s += '{}: {}{}\n'.format(member[0], ' ' * (max_length - len(member[0])), member_value)
        s = s[:-1]
        return s

class GPO(ADObject):
    pass

class PSO(ADObject):
    pass

class GptTmpl(ADObject):
    def __str__(self):
        s = str()
        members = inspect.getmembers(self, lambda x: not(inspect.isroutine(x)))
        for member in members:
            if not member[0].startswith('_'):
                s += '{}:\n'.format(member[0])
                member_value_str = str(member[1])
                for line in member_value_str.split('\n'):
                    s += '\t{}\n'.format(line)

        s = s[:-1]
        return s

class GPOGroup(ADObject):
    pass

class Policy(ADObject):
    pass

class GPOComputerAdmin(ADObject):
    pass

class GPOLocation(ADObject):
    pass

