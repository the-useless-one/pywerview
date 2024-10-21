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

import inspect
import logging

from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR

import pywerview.functions.misc as misc

class ADObject:
    _well_known_sids = {'S-1-0-0': 'Nobody', 'S-1-0': 'Null Authority', 'S-1-1-0': 'Everyone',
                        'S-1-1': 'World Authority', 'S-1-2-0': 'Local', 'S-1-2-1': 'Console Logon',
                        'S-1-2': 'Local Authority', 'S-1-3-0': 'Creator Owner', 'S-1-3-1': 'Creator Group',
                        'S-1-3-2': 'Creator Owner Server', 'S-1-3-3': 'Creator Group Server', 'S-1-3-4': 'Owner Rights',
                        'S-1-3': 'Creator Authority', 'S-1-4': 'Non-unique Authority', 'S-1-5-10': 'Principal Self',
                        'S-1-5-11': 'Authenticated Users', 'S-1-5-12': 'Restricted Code', 'S-1-5-13': 'Terminal Server Users',
                        'S-1-5-14': 'Remote Interactive Logon', 'S-1-5-17': 'This Organization', 'S-1-5-18': 'Local System',
                        'S-1-5-19': 'NT Authority', 'S-1-5-1': 'Dialup', 'S-1-5-20': 'NT Authority', 'S-1-5-2': 'Network',
                        'S-1-5-32-544': 'Administrators' ,'S-1-5-32-546': 'Guests', 'S-1-5-32-547': 'Power Users',
                        'S-1-5-32-548': 'Account Operators', 'S-1-5-32-549': 'Server Operators',
                        'S-1-5-32-550': 'Print Operators', 'S-1-5-32-551': 'Backup Operators', 'S-1-5-32-552': 'Replicators',
                        'S-1-5-32-554': 'Builtin\\Pre-Windows 2000 Compatible Access',
                        'S-1-5-32-555': 'Builtin\\Remote Desktop Users',
                        'S-1-5-32-556': 'Builtin\\Network Configuration Operators',
                        'S-1-5-32-557': 'Builtin\\Incoming Forest Trust Builders',
                        'S-1-5-32-558': 'Builtin\\Performance Monitor Users',
                        'S-1-5-32-559': 'Builtin\\Performance Log Users',
                        'S-1-5-32-560': 'Builtin\\Windows Authorization Access Group',
                        'S-1-5-32-561': 'Builtin\\Terminal Server License Servers',
                        'S-1-5-32-562': 'Builtin\\Distributed COM Users',
                        'S-1-5-32-568': 'Builtin\\IIS_IUSRS',
                        'S-1-5-32-569': 'Builtin\\Cryptographic Operators',
                        'S-1-5-32-573': 'Builtin\\Event Log Readers',
                        'S-1-5-32-574': 'Builtin\\Certificate Service DCOM Access',
                        'S-1-5-32-575': 'Builtin\\RDS Remote Access Servers',
                        'S-1-5-32-576': 'Builtin\\RDS Endpoint Servers',
                        'S-1-5-32-577': 'Builtin\\RDS Management Servers',
                        'S-1-5-32-578': 'Builtin\\Hyper-V Administrators',
                        'S-1-5-32-579': 'Builtin\\Access Control Assistance Operators',
                        'S-1-5-32-580': 'Builtin\\Remote Management Users',
                        'S-1-5-32-582': 'Storage Replica Administrators',
                        'S-1-5-3': 'Batch', 'S-1-5-4': 'Interactive', 'S-1-5-64-10': 'NTLM Authentication',
                        'S-1-5-64-14': 'SChannel Authentication', 'S-1-5-64-21': 'Digest Authentication',
                        'S-1-5-6': 'Service', 'S-1-5-7': 'Anonymous', 'S-1-5-80-0': 'NT Services\\All Services',
                        'S-1-5-80': 'NT Service', 'S-1-5-8': 'Proxy', 'S-1-5-9': 'Enterprise Domain Controllers',
                        'S-1-5': 'NT Authority'}

    _well_known_rids = { '498' : 'Enterprise Read-only Domain Controllers',
                         '512' : 'Domain Admins', '513' : 'Domain Users', '514' : 'Domain Guests', '515' : 'Domain Computers',
                         '516' : 'Domain Controllers', '517' : 'Cert Publishers', '519' : 'Enterprise Admins',
                         '520' : 'Group Policy Creator Owners', '522' : 'Cloneable Domain COntrollers', '526' : 'Key Admins',
                         '527' : 'Enterptise Key Admins', '553' : 'RAS and IAS Servers'}

    def __init__(self, attributes):
        logger = logging.getLogger('pywerview_main_logger.ADObject')
        logger.ULTRA = 5
        self._logger = logger

        self._attributes_dict = dict()
        self.add_attributes(attributes)

    def add_attributes(self, attributes):
        self._logger.log(self._logger.ULTRA,'ADObject instancied with the following attributes : {}'.format(attributes))
        for attr in attributes:
            self._attributes_dict[attr.lower()] = attributes[attr]

    def __getattr__(self, attr):
        try:
            return self._attributes_dict[attr]
        except KeyError:
            if attr == 'isgroup':
                try:
                    return 'group' in self._attributes_dict['objectclass']
                except KeyError:
                    return False
            raise AttributeError

    # In this method, we try to pretty print common AD attributes
    def __str__(self):
        s = str()
        max_length = 0
        for attr in self._attributes_dict:
            if len(attr) > max_length:
                max_length = len(attr)
        for attr in self._attributes_dict:
            attribute = self._attributes_dict[attr]
            self._logger.log(self._logger.ULTRA,'Trying to print : attribute name = {0} / value = {1}'.format(attr, attribute))
            if isinstance(attribute, list):
                if any(isinstance(x, bytes) for x in attribute):
                    attribute = ['{}...'.format(x.hex()[:97]) for x in attribute]
                attribute_temp = ', '.join(str(x) for x in attribute)
                if len(attribute_temp) > 100:
                    attribute_temp = str()
                    line = str()
                    for x in attribute:
                        if len(line) + len(str(x)) <= 100:
                            line += '{}, '.format(x)
                        else:
                            attribute_temp += line + '\n' + ' ' * (max_length + 2)
                            line = str()
                            line += '{}, '.format(x)
                    attribute_temp += line + '\n' + ' ' * (max_length + 2)
                attribute = attribute_temp.rstrip().rstrip(',')
            elif isinstance(attribute, bytes):
                attribute = '{}...'.format(attribute.hex()[:100])
            elif isinstance(attribute, ADObject):
                attribute = ('\n' + str(attribute)).replace('\n', '\n\t')

            s += '{}: {}{}\n'.format(attr, ' ' * (max_length - len(attr)), attribute)

        s = s[:-1]
        return s

    def __repr__(self):
        return str(self)

    def to_json(self):
        return self._attributes_dict

class ACE(ADObject):

    def __init__(self, attributes):
        ADObject.__init__(self, attributes)

        # We set iscallback, depending on the type of ACE
        self._attributes_dict['iscallbak'] = ('CALLBACK' in self.acetype)

class User(ADObject):
    pass

class Group(ADObject):
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
    pass

class GPO(ADObject):
    pass

class PSO(ADObject):
    pass

class GptTmpl(ADObject):
    def to_json(self):
        json_dict = {}
        for k, v in self._attributes_dict.items():
            json_dict[k] = v.to_json()
        return json_dict

class GPOGroup(ADObject):
    pass

class Policy(ADObject):
    pass

class GPOComputerAdmin(ADObject):
    pass

class GPOLocation(ADObject):
    pass

class GMSAAccount(ADObject):
    pass

class SMSAAccount(ADObject):
    pass

class ObjectOwner(ADObject):
    pass

class PKIEnrollmentService(ADObject):
    _enrollment_uuids = { "All-Extended-Rights" : "00000000-0000-0000-0000-000000000000",
                          "Certificate-Enrollment" : "0e10c968-78fb-11d2-90d4-00c04f79dc55",
                          "Certificate-AutoEnrollment" : "a05b8cc2-17bc-4802-a710-e7c15ab866a2"}
    pass

class PKICertificateTemplate(PKIEnrollmentService):
    pass
