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

from pywerview.objects.adobjects import *
from pywerview.requester import LDAPRequester

class GPORequester(LDAPRequester):

    def get_netgpo(self, queried_gponame='*', queried_displayname=str(),
                   queried_domain=str(), ads_path=str()):

        self._create_ldap_connection(queried_domain=queried_domain, ads_path=ads_path)

        gpo_search_filter = ldapasn1.Filter()
        gpo_search_filter['and'] = ldapasn1.And()

        gpo_filter = LDAPRequester._build_equality_match_filter('objectCategory', 'groupPolicyContainer')
        gpo_search_filter['and'][0] = gpo_filter

        if queried_displayname:
            if '*' in queried_displayname:
                displayname_filter = LDAPRequester._build_substrings_filter('displayname', queried_displayname)
            else:
                displayname_filter = LDAPRequester._build_equality_match_filter('displayname', queried_displayname)
            gpo_search_filter['and'][gpo_search_filter['and']._componentValuesSet] = displayname_filter
        else:
            if '*' in queried_gponame:
                gponame_filter = LDAPRequester._build_substrings_filter('displayname', queried_gponame)
            else:
                gponame_filter = LDAPRequester._build_equality_match_filter('displayname', queried_gponame)
            gpo_search_filter['and'][gpo_search_filter['and']._componentValuesSet] = gponame_filter

        return self._ldap_search(gpo_search_filter, GPO)

