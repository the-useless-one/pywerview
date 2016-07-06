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

import socket
import sys

from impacket.ldap import ldap, ldapasn1
import impacket.dcerpc.v5.rpcrt
import pywerview.net
from pywerview._rpc import *

def build_domain_connection(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(),
        ads_prefix=str(), ads_path=str()):

    if not queried_domain:
        queried_domain = domain

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
        domain_connection = ldap.LDAPConnection('ldap://{}'.format(domain_controller),
            base_dn, domain_controller)
    except socket.error, e:
        print >>sys.stderr, e
        sys.exit(-1)
    except ldap.LDAPSessionError, e:
        if str(e).find('strongerAuthRequired') >= 0:
            # We need to try SSL
            domain_connection = ldap.LDAPConnection('ldaps://{}'.format(domain_controller),
                    base_dn, domain_controller)
        else:
            print >>sys.stderr, e
            sys.exit(-1)

    try:
        domain_connection.login(user, password, domain, lmhash, nthash)
    except ldap.LDAPSessionError, e:
        print >>sys.stderr, e
        sys.exit(-1)

    return domain_connection

def get_domainsid(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str()):

    domain_controllers = pywerview.net.get_netdomaincontroller(domain_controller, domain, user, password,
            lmhash, nthash, queried_domain)

    if domain_controllers:
        primary_dc = domain_controllers[0]
        domain_sid = '-'.join(primary_dc.objectsid.split('-')[:-1])
    else:
        domain_sid = None

    return domain_sid

def invoke_checklocaladminaccess(target_computername, domain, user,
        password=str(), lmhash=str(), nthash=str()):

    dce = build_dce(domain, user, password, lmhash, nthash, target_computername, r'\svcctl')

    try:
        ans = scmr.hROpenSCManagerW(dce)
    except impacket.dcerpc.v5.rpcrt.DCERPCException:
        return False

    return True

