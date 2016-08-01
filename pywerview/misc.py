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
from impacket.smbconnection import SMBConnection
import impacket.dcerpc.v5.rpcrt
import pywerview.net
from pywerview._rpc import *

def build_domain_connection(domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str(), queried_domain=str(),
        ads_prefix=str(), ads_path=str()):

    if not domain:
        domain = get_netfqdn(domain_controller)

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

def convert_sidtont4(sid, domain_controller, domain, user, password=str(),
        lmhash=str(), nthash=str()):

    stringBinding = epm.hept_map(domain_controller, drsuapi.MSRPC_UUID_DRSUAPI,
                                 protocol='ncacn_ip_tcp')
    rpc = transport.DCERPCTransportFactory(stringBinding)
    if hasattr(rpc, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpc.set_credentials(username=user, password=password, domain=domain,
                lmhash=lmhash, nthash=nthash)
    dce = build_dce(domain, user, password, lmhash, nthash, domain_controller, r'\drsuapi')

    # We get a DRS handle
    request = drsuapi.DRSBind()
    request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
    drs = drsuapi.DRS_EXTENSIONS_INT()
    drs['cb'] = len(drs) #- 4
    drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | \
                     drsuapi.DRS_EXT_STRONG_ENCRYPTION
    drs['SiteObjGuid'] = drsuapi.NULLGUID
    drs['Pid'] = 0
    drs['dwReplEpoch'] = 0
    drs['dwFlagsExt'] = 0
    drs['ConfigObjGUID'] = drsuapi.NULLGUID
    drs['dwExtCaps'] = 0xffffffff
    request['pextClient']['cb'] = len(drs)
    request['pextClient']['rgb'] = list(str(drs))

    hdrs = dce.request(request)['phDrs']

    resp = drsuapi.hDRSCrackNames(dce, hdrs, 0x0, 11, 2, (sid,))

    return resp['pmsgOut']['V1']['pResult']['rItems'][0]['pName']

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

def get_netfqdn(target_computername):
    smb = SMBConnection(target_computername, target_computername)
    smb.login('', '')

    return smb.getServerDNSDomainName()

def invoke_checklocaladminaccess(target_computername, domain, user,
        password=str(), lmhash=str(), nthash=str()):

    dce = build_dce(domain, user, password, lmhash, nthash, target_computername, r'\svcctl')

    try:
        # 0xF003F - SC_MANAGER_ALL_ACCESS
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx

        ans = scmr.hROpenSCManagerW(dce, '{}\x00'.format(target_computername), 'ServicesActive\x00', 0xF003F)
    except impacket.dcerpc.v5.rpcrt.DCERPCException:
        return False

    return True

