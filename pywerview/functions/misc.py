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

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import scmr, drsuapi

from pywerview.requester import LDAPRPCRequester
import pywerview.functions.net

class Misc(LDAPRPCRequester):
    @LDAPRPCRequester._rpc_connection_init(r'\drsuapi')
    def convert_sidtont4(self, sid):

        # We get a DRS handle, shamelessly stolen from secretsdump.py
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

        hdrs = self._rpc_connection.request(request)['phDrs']

        resp = drsuapi.hDRSCrackNames(self._rpc_connection, hdrs, 0x0, 11, 2, (sid,))

        return resp['pmsgOut']['V1']['pResult']['rItems'][0]['pName']

    def get_domainsid(self, queried_domain=str()):

        with pywerview.functions.net.NetRequester(self._domain_controller, self._domain, self._user,
                                                  self._password, self._lmhash, self._nthash) as r:
            domain_controllers = r.get_netdomaincontroller(queried_domain=queried_domain)

        if domain_controllers:
            primary_dc = domain_controllers[0]
            domain_sid = '-'.join(primary_dc.objectsid.split('-')[:-1])
        else:
            domain_sid = None

        return domain_sid

    @LDAPRPCRequester._rpc_connection_init(r'\svcctl')
    def invoke_checklocaladminaccess(self):

        try:
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            ans = scmr.hROpenSCManagerW(self._rpc_connection,
                                        '{}\x00'.format(self._target_computer),
                                        'ServicesActive\x00', 0xF003F)
        except DCERPCException:
            return False

        return True

