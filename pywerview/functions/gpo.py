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

import codecs
from StringIO import StringIO

from impacket.ldap import ldapasn1
from impacket.smbconnection import SMBConnection

from pywerview.objects.adobjects import *
from pywerview.requester import LDAPRequester

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
        content_io = StringIO()

        gpttmpl_path_split = gpttmpl_path.split('\\')
        target = gpttmpl_path_split[2]
        share = gpttmpl_path_split[3]
        file_name = '\\'.join(gpttmpl_path_split[4:])

        smb_connection = SMBConnection(remoteName=target, remoteHost=target)
        # TODO: kerberos login
        smb_connection.login(self._user, self._password, self._domain,
                             self._lmhash, self._nthash)

        smb_connection.connectTree(share)
        smb_connection.getFile(share, file_name, content_io.write)

        content = codecs.decode(content_io.getvalue(), 'utf_16_le')[1:].replace('\r', '')

        sections_final = dict()
        for l in content.split('\n'):
            if l.startswith('['):
                section_name = l.strip('[]')
                sections_final[section_name] = dict()
            elif '=' in l:
                property_name, property_values = [x.strip() for x in l.split('=')]
                if ',' in property_values:
                    property_values = property_values.split(',')
                sections_final[section_name][property_name] =  property_values

        return sections_final

