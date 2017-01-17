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

from __future__ import unicode_literals

import inspect

class RPCObject:
    def __init__(self, obj):
        attributes = dict()
        try:
            for key in obj.fields.keys():
                attributes[key] = obj[key]
        except AttributeError:
            attributes = obj
        self.add_attributes(attributes)

    def add_attributes(self, attributes):
        for key, value in attributes.items():
            key = key.lower()
            if key in ('wkui1_logon_domain', 'wkui1_logon_server',
                       'wkui1_oth_domains', 'wkui1_username',
                       'sesi10_cname', 'sesi10_username'):
                value = value.rstrip('\x00')
            if isinstance(value, str):
                try:
                    value = value.decode('utf-8')
                except UnicodeDecodeError:
                    pass

            setattr(self, key.lower(), value)

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
                s += '{}: {}{}\n'.format(member[0], ' ' * (max_length - len(member[0])), member[1])

        s = s[:-1].encode('utf-8')
        return s

    def __repr__(self):
        return str(self)

class TargetUser(RPCObject):
    pass

class Session(RPCObject):
    pass

class Share(RPCObject):
    pass

class WkstaUser(RPCObject):
    pass

class Group(RPCObject):
    pass

class Disk(RPCObject):
    pass

class Process(RPCObject):
    def __init__(self, obj):
        RPCObject.__init__(self, obj)
        self.user = str(self.user)
        self.domain = str(self.domain)

class Event(RPCObject):
    pass

