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
import codecs

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

    def __init__(self, attributes):
        self.add_attributes(attributes)

    def add_attributes(self, attributes):
        for attr in attributes:
            #print(attr)
            #print(attributes[attr], attr)
            t = str(attr).lower()
            if t in ('logonhours', 'msds-generationid'):
                value = bytes(attributes[attr][0])
                value = [x for x in value]
            elif t in ('trustattributes', 'trustdirection', 'trusttype'):
                value = int(attributes[attr][0])
            elif t in ('objectsid', 'ms-ds-creatorsid'):
                value = codecs.encode(bytes(attributes[attr][0]),'hex')
                init_value = bytes(attributes[attr][0])
                value = 'S-{0}-{1}'.format(init_value[0], init_value[1])
                for i in range(8, len(init_value), 4):
                    value += '-{}'.format(str(struct.unpack('<I', init_value[i:i+4])[0]))
            elif t == 'objectguid':
                init_value = bytes(attributes[attr][0])
                value = str()
                value += '{}-'.format(hex(struct.unpack('<I', init_value[0:4])[0])[2:].zfill(8))
                value += '{}-'.format(hex(struct.unpack('<H', init_value[4:6])[0])[2:].zfill(4))
                value += '{}-'.format(hex(struct.unpack('<H', init_value[6:8])[0])[2:].zfill(4))
                value += '{}-'.format((codecs.encode(init_value,'hex')[16:20]).decode('utf-8'))
                value += init_value.hex()[20:]
            elif t in ('dscorepropagationdata', 'whenchanged', 'whencreated'):
                value = list()
                for val in attributes[attr]:
                    value.append(str(datetime.strptime(str(val.decode('utf-8')), '%Y%m%d%H%M%S.0Z')))
            elif t in ('accountexpires', 'pwdlastset', 'badpasswordtime', 'lastlogontimestamp', 'lastlogon', 'lastlogoff'):
                try:
                    filetimestamp = int(attributes[attr][0].decode('utf-8'))
                    if filetimestamp != 9223372036854775807:
                        timestamp = (filetimestamp - 116444736000000000)/10000000
                        value = datetime.fromtimestamp(0) + timedelta(seconds=timestamp)
                    else:
                        value = 'never'
                except IndexError:
                    value = 'empty'
            elif t == 'isgroup':
                value = attributes[attr]
            elif t == 'objectclass':
                value = [x.decode('utf-8') for x in attributes[attr]]
                setattr(self, 'isgroup', ('group' in value))
            elif len(attributes[attr]) > 1:
                try:
                    value = [x.decode('utf-8') for x in attributes[attr]]
                except (UnicodeDecodeError):
                    value = [x for x in attributes[attr]]
                except (AttributeError):
                    value = attributes[attr]
            else:
                try:
                    value = attributes[attr][0].decode('utf-8')
                except (IndexError):
                    value = str()
                except (UnicodeDecodeError):
                    value = attributes[attr][0]

            setattr(self, t, value)

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
                if member[0] == 'msmqdigests':
                    member_value = (',\n' + ' ' * (max_length + 2)).join(x.hex() for x in member[1])
                elif member[0] == 'useraccountcontrol':
                    member_value = list()
                    for uac_flag, uac_label in ADObject.__uac_flags.items():
                        if int(member[1]) & uac_flag == uac_flag:
                            member_value.append(uac_label)
                elif isinstance(member[1], list):
                    if member[0] in ('logonhours',):
                        member_value = member[1]
                    elif member[0] in ('usercertificate',
                                       'protocom-sso-entries', 'protocom-sso-security-prefs',):
                        member_value = (',\n' + ' ' * (max_length + 2)).join(
                                '{}...'.format(x.hex()[:100]) for x in member[1])
                    else:
                        member_value = (',\n' + ' ' * (max_length + 2)).join(str(x) for x in member[1])
                elif member[0] in('msmqsigncertificates', 'userparameters',
                                  'jpegphoto', 'thumbnailphoto', 'usercertificate',
                                  'msexchmailboxguid', 'msexchmailboxsecuritydescriptor',
                                  'msrtcsip-userroutinggroupid', 'msexchumpinchecksum',
                                  'protocom-sso-auth-data', 'protocom-sso-entries-checksum',
                                  'protocom-sso-security-prefs-checksum', ):
                    # Attribut exists but it is empty
                    try:
                        member_value = '{}...'.format(member[1].hex()[:100])
                    except AttributeError:
                        member_value = ''
                else:
                    member_value = member[1]
                s += '{}: {}{}\n'.format(member[0], ' ' * (max_length - len(member[0])), member_value)

        s = s[:-1]
        return s

    def __repr__(self):
        return str(self)

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
    def __init__(self, attributes):
        ADObject.__init__(self, attributes)
        self.distinguishedname = 'LDAP://{}'.format(self.distinguishedname)

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

    def __init__(self, attributes):
        ad_obj = ADObject(attributes)
        self.targetname = ad_obj.name

        self.trustdirection = Trust.__trust_direction.get(ad_obj.trustdirection, 'unknown')
        self.trusttype = Trust.__trust_type.get(ad_obj.trusttype, 'unknown')
        self.whencreated = ad_obj.whencreated
        self.whenchanged = ad_obj.whenchanged

        self.trustattributes = list()
        for attrib_flag, attrib_label in Trust.__trust_attrib.items():
            if ad_obj.trustattributes & attrib_flag:
                self.trustattributes.append(attrib_label)

        # If the filter SIDs attribute is not manually set, we check if we're
        # not in a use case where SIDs are implicitly filtered
        # Based on https://github.com/vletoux/pingcastle/blob/master/Healthcheck/TrustAnalyzer.cs
        if 'filter_sids' not in self.trustattributes:
            if not (self.trustdirection == 'disabled' or \
                    self.trustdirection == 'inbound' or \
                    'within_forest' in self.trustattributes or \
                    'pim_trust' in self.trustattributes):
                if 'forest_transitive' in self.trustattributes and 'treat_as_external' not in self.trustattributes:
                    self.trustattributes.append('filter_sids')

class GPO(ADObject):
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

