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
import impacket.smbconnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm

def build_dce(domain, user, password, lmhash, nthash, target_computer, pipe):
    binding_strings = dict()
    binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
    binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
    binding_strings['samr'] = samr.MSRPC_UUID_SAMR
    binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
    binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

    # TODO: try to fallback to TCP/139 if tcp/445 is closed
    if pipe == r'\drsuapi':
        string_binding = epm.hept_map(target_computer, drsuapi.MSRPC_UUID_DRSUAPI,
                                     protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(username=user, password=password, domain=domain,
                lmhash=lmhash, nthash=nthash)
    else:
        rpctransport = transport.SMBTransport(target_computer, 445, pipe,
                username=user, password=password, domain=domain, lmhash=lmhash,
                nthash=nthash)

    rpctransport.set_connect_timeout(10)
    dce = rpctransport.get_dce_rpc()
    if pipe == r'\drsuapi':
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    try:
        dce.connect()
    except (socket.error, impacket.smbconnection.SessionError):
        return None

    dce.bind(binding_strings[pipe[1:]])

    return dce

