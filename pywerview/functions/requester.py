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

from impacket.ldap import ldap, ldapasn1

class LDAPRequester():
    def __init__(self, domain_controller, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str()):
        self._domain_controller = domain_controller
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._ldap_connection = None

    def _create_ldap_connection(self, queried_domain=str(), ads_path=str(),
                                ads_prefix=str()):
        if not self._domain:
            self._domain = _get_netfqdn(self._domain_controller)

        if not queried_domain:
            queried_domain = self._domain

        base_dn = str()

        if ads_prefix:
            base_dn = '{},'.format(ads_prefix)

        if ads_path:
            # TODO: manage ADS path starting with 'GC://'
            if ads_path.upper().startswith('LDAP://'):
                ads_path = ads_path[7:]
            base_dn += ads_path
        else:
            base_dn += ','.join('dc={}'.format(x) for x in queried_domain.split('.'))

        try:
            ldap_connection = ldap.LDAPConnection('ldap://{}'.format(self._domain_controller),
                                                  base_dn, self._domain_controller)
        except ldap.LDAPSessionError, e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldap_connection = ldap.LDAPConnection('ldaps://{}'.format(self._domain_controller),
                                                      base_dn, self._domain_controller)
            else:
                raise e

        ldap_connection.login(self._user, self._password, self._domain,
                              self._lmhash, self._nthash)

        self._ldap_connection = ldap_connection

    def _ldap_search(self, search_filter, class_result, attributes=list()):
        results = list()
        try:
            search_results = self._ldap_connection.search(manualFilter=search_filter,
                                                          attributes=attributes)
        except ldap.LDAPSearchError as e:
            # If we got a "size exceeded" error, we get the partial results
            if e.error == 4:
                search_results = e.answers
            else:
                raise e

        for result in search_results:
            if not isinstance(result, ldapasn1.SearchResultEntry):
                continue

            results.append(class_result(result['attributes']))

        return results

    @staticmethod
    def _build_extensible_match_filter(matching_rule, match_type, match_value):
        f = ldapasn1.Filter()
        f['extensibleMatch'] = ldapasn1.MatchingRuleAssertion()
        f['extensibleMatch']['matchingRule'] = ldapasn1.MatchingRuleId(matching_rule)
        f['extensibleMatch']['type'] = ldapasn1.TypeDescription(match_type)
        f['extensibleMatch']['matchValue'] = ldapasn1.matchValueAssertion(match_value)
        f['extensibleMatch']['dnAttributes'] = False

        return f

    @staticmethod
    def _build_equality_match_filter(attribute_desc, attribute_value):
        f = ldapasn1.Filter()
        f['equalityMatch'] = ldapasn1.EqualityMatch()
        f['equalityMatch']['attributeDesc'] = ldapasn1.AttributeDescription(attribute_desc)
        f['equalityMatch']['assertionValue'] = ldapasn1.AssertionValue(attribute_value)

        return f

    @staticmethod
    def _build_substrings_filter(attribute_desc, attribute_value):
        f = ldapasn1.Filter()

        if attribute_value == '*':
            f['present'] = ldapasn1.Present(attribute_desc)
        else:
            substrings = attribute_value.split('*')
            f['substrings'] = ldapasn1.SubstringFilter()
            f['substrings']['type'] = ldapasn1.AttributeDescription(attribute_desc)
            f['substrings']['substrings'] = ldapasn1.SubStrings()
            offset = 0
            if substrings[0]:
                f['substrings']['substrings'][0] = ldapasn1.SubString().setComponentByName('initial', ldapasn1.InitialAssertion(substrings[0]))
                offset = 1
            for i, substring in enumerate(substrings[1:-1]):
                f['substrings']['substrings'][i+offset] = ldapasn1.SubString().setComponentByName('any', ldapasn1.AnyAssertion(substring))
            if substrings[-1]:
                f['substrings']['substrings'][len(substrings)-2+offset] = ldapasn1.SubString().setComponentByName('final', ldapasn1.FinalAssertion(substrings[-1]))

        return f

