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

from impacket.dcerpc.v5 import transport, wkst, srvs, samr

def _build_dce(domain, user, password, lmhash, nthash, string_binding):
    # TODO: try to fallback to TCP/139 if tcp/445 is closed
    rpctransport = transport.DCERPCTransportFactory(string_binding)

    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(user, password, domain, lmhash, nthash)

    dce = rpctransport.get_dce_rpc()
    dce.connect()

    if 'srvsvc' in string_binding:
        dce.bind(srvs.MSRPC_UUID_SRVS)
    elif 'wkssvc' in string_binding:
        dce.bind(wkst.MSRPC_UUID_WKST)
    elif 'samr' in string_binding:
        dce.bind(samr.MSRPC_UUID_SAMR)

    return dce

def build_srvs_dce(domain, user, password, lmhash, nthash, target_computername):
    string_srvs_binding = r'ncacn_np:{}[\PIPE\srvsvc]'.format(target_computername)
    return _build_dce(domain, user, password, lmhash, nthash, string_srvs_binding)

def build_wkssvc_dce(domain, user, password, lmhash, nthash, target_computername):
    string_wkssvc_binding = r'ncacn_np:{}[\PIPE\wkssvc]'.format(target_computername)
    return _build_dce(domain, user, password, lmhash, nthash, string_wkssvc_binding)

def build_samr_dce(domain, user, password, lmhash, nthash, target_computername):
    string_samr_binding = r'ncacn_np:{}[\PIPE\samr]'.format(target_computername)
    return _build_dce(domain, user, password, lmhash, nthash, string_samr_binding)

