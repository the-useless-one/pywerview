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


def build_extensible_match_filter(matching_rule, match_type, match_value):
    f = ldapasn1.Filter()
    f['extensibleMatch'] = ldapasn1.MatchingRuleAssertion()
    f['extensibleMatch']['matchingRule'] = ldapasn1.MatchingRuleId(matching_rule)
    f['extensibleMatch']['type'] = ldapasn1.TypeDescription(match_type)
    f['extensibleMatch']['matchValue'] = ldapasn1.matchValueAssertion(match_value)
    f['extensibleMatch']['dnAttributes'] = False

    return f

def build_equality_match_filter(attribute_desc, attribute_value):
    f = ldapasn1.Filter()
    f['equalityMatch'] = ldapasn1.EqualityMatch()
    f['equalityMatch']['attributeDesc'] = ldapasn1.AttributeDescription(attribute_desc)
    f['equalityMatch']['assertionValue'] = ldapasn1.AssertionValue(attribute_value)

    return f

def build_substrings_filter(attribute_desc, attribute_value):
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

