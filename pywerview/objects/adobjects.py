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

from datetime import datetime
import inspect
import struct

class ADObject:
    def __init__(self, attributes):
        self.add_attributes(attributes)

    def add_attributes(self, attributes):
        for attr in attributes:
            t = str(attr['type']).lower()
            if t in ('logonhours', 'msds-generationid'):
                value = str(attr['vals'][0])
                value = [ord(x) for x in value]
            elif t in ('objectsid', 'ms-ds-creatorsid'):
                value = str(attr['vals'][0]).encode('hex')
                init_value = str(attr['vals'][0])
                value = 'S-1-5'
                for i in xrange(8, len(init_value), 4):
                    value += '-{}'.format(str(struct.unpack('<I', init_value[i:i+4])[0]))
            elif t == 'objectguid':
                init_value = str(attr['vals'][0])
                value = str()
                value += '{}-'.format(hex(struct.unpack('<I', init_value[0:4])[0])[2:].zfill(8))
                value += '{}-'.format(hex(struct.unpack('<H', init_value[4:6])[0])[2:].zfill(4))
                value += '{}-'.format(hex(struct.unpack('<H', init_value[6:8])[0])[2:].zfill(4))
                value += '{}-'.format(init_value.encode('hex')[16:20])
                value += init_value.encode('hex')[20:]
            elif t in ('dscorepropagationdata', 'whenchanged', 'whencreated'):
                value = list()
                for val in attr['vals']:
                    value.append(str(datetime.strptime(str(val), '%Y%m%d%H%M%S.0Z')))
            elif t in ('pwdlastset', 'badpasswordtime', 'lastlogon', 'lastlogoff'):
                timestamp = (int(str(attr['vals'][0])) - 116444736000000000)/10000000
                value = datetime.fromtimestamp(timestamp)
            elif t == 'isgroup':
                value = attr['vals'][0]
            elif t == 'objectclass':
                value = [str(x) for x in attr['vals']]
                setattr(self, 'isgroup', ('group' in value))
            elif len(attr['vals']) > 1:
                value = [str(x) for x in attr['vals']]
            else:
                try:
                    value = str(attr['vals'][0])
                except IndexError:
                    value = str()

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
                    member_value = (',\n' + ' ' * (max_length + 2)).join(x.encode('hex') for x in member[1])
                elif isinstance(member[1], list):
                    if member[0] in ('logonhours',):
                        member_value = member[1]
                    elif member[0] in ('usercertificate',):
                        member_value = (',\n' + ' ' * (max_length + 2)).join(
                                '{}...'.format(x.encode('hex')[:100]) for x in member[1])
                    else:
                        member_value = (',\n' + ' ' * (max_length + 2)).join(str(x) for x in member[1])
                elif member[0] in('msmqsigncertificates', 'userparameters',
                                  'jpegphoto', 'thumbnailphoto', 'usercertificate',
                                  'msexchmailboxguid', 'msexchmailboxsecuritydescriptor',
                                  'msrtcsip-userroutinggroupid', 'msexchumpinchecksum'):
                    member_value = '{}...'.format(member[1].encode('hex')[:100])
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
        for attr in ('homedirectory', 'scriptpath', 'profilepath'):
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

