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

# Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2023

import sys
import logging
import socket
import ntpath
import ldap3
import os
import tempfile
import ssl

from ldap3.protocol.formatters.formatters import *

from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError
from impacket.krb5.ccache import CCache, Credential, CountedOctetString
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr, drsuapi, epm
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException

import pywerview.formatters as fmt

class LDAPRequester():
    def __init__(self, domain_controller, domain=str(), user=str(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False, do_tls=False,
                 user_cert=str(), user_key=str()):
        self._domain_controller = domain_controller
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._do_certificate = user_cert and user_key
        self._user_cert = user_cert
        self._user_key = user_key
        self._do_tls = do_tls
        self._queried_domain = None
        self._ads_path = None
        self._ads_prefix = None
        self._ldap_connection = None
        self._base_dn = None
        self._server_info = None

        # Call custom formatters for several AD attributes
        self._formatter = {'userAccountControl': fmt.format_useraccountcontrol,
                'sAMAccountType': fmt.format_samaccounttype,
                'trustType': fmt.format_trusttype,
                'trustDirection': fmt.format_trustdirection,
                'trustAttributes': fmt.format_trustattributes,
                'msDS-MaximumPasswordAge': format_ad_timedelta,
                'msDS-MinimumPasswordAge': format_ad_timedelta,
                'msDS-LockoutDuration': format_ad_timedelta,
                'msDS-LockoutObservationWindow': format_ad_timedelta,
                'msDS-GroupMSAMembership': fmt.format_groupmsamembership,
                'msDS-ManagedPassword': fmt.format_managedpassword,
                'ms-Mcs-AdmPwdExpirationTime': format_ad_timestamp,
                'securityIdentifier': format_sid,
                'pKIExtendedKeyUsage': fmt.format_ekus,
                'msPKI-Enrollment-Flag': fmt.format_mspkienrollmentflag}

        logger = logging.getLogger('pywerview_main_logger.LDAPRequester')
        logger.ULTRA = 5
        self._logger = logger

        # We check here if the ldap3 install supports NTLM and Kerberos encryption
        # along with TLS channel binding
        # Run `pip install ldap3-bleeding-edge` to install it
        try:
            if ldap3.SIGN and ldap3.ENCRYPT:
                self._sign_and_seal_supported = True
                self._logger.debug('LDAP sign and seal are supported')
        except AttributeError:
            self._sign_and_seal_supported = False
            self._logger.debug('LDAP sign and seal are not supported')

        try:
            if ldap3.TLS_CHANNEL_BINDING:
                self._tls_channel_binding_supported = True
                self._logger.debug('TLS channel binding is supported')
        except AttributeError:
            self._tls_channel_binding_supported = False
            self._logger.debug('TLS channel binding is not supported')

    def _parse_ldap_invalid_credentials_result_message(self, message):
        # https://ldapwiki.com/wiki/Wiki.jsp?page=Common%20Active%20Directory%20Bind%20Errors
        error_codes = {
                        0x52e      : "ERROR_LOGON_FAILURE",
                        0x52f      : "ERROR_ACCOUNT_RESTRICTION",
                        0x530      : "ERROR_INVALID_LOGON_HOURS",
                        0x531      : "ERROR_INVALID_WORKSTATION",
                        0x532      : "ERROR_PASSWORD_EXPIRED",
                        0x533      : "ERROR_ACCOUNT_DISABLED",
                        0x701      : "ERROR_ACCOUNT_EXPIRED",
                        0x703      : "ERROR_PASSWORD_MUST_CHANGE",
                        0x775      : "ERROR_ACCOUNT_LOCKED_OUT",
                        0x80090346 : "SEC_E_BAD_BINDINGS"
                      }
        try:
            # Message is something like:
            # 80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 775, v4563
            # we need to extract the "data" code
            data_code = message.split(": ")[3].split(', ')[1].strip(" data")
            data_code = int(data_code,16)
            parsed_code = error_codes[data_code]
        except(IndexError, KeyError):
            self._logger.warning('Unable to parse error code')
            return message
        return parsed_code

    def _do_ntlm_auth(self, server, seal_and_sign=False, tls_channel_binding=False):
        self._logger.debug('LDAP authentication with NTLM: ldap_scheme = {0} / seal_and_sign = {1} / tls_channel_binding = {2}'.format(
                            "ldaps" if server.ssl else "ldap", seal_and_sign, tls_channel_binding))
        ldap_connection_kwargs = {'server': server, 'user': '{}\\{}'.format(self._domain, self._user),
                                  'raise_exceptions': True, 'authentication': ldap3.NTLM}

        if self._lmhash and self._nthash:
            ldap_connection_kwargs['password'] = '{}:{}'.format(self._lmhash, self._nthash)
        else:
            ldap_connection_kwargs['password'] = self._password
        self._logger.debug('LDAP binding parameters: server = {0} / user = {1} '
            '/ password = {2}'.format(self._domain_controller, self._user, ldap_connection_kwargs['password']))

        if seal_and_sign:
            ldap_connection_kwargs['session_security'] = ldap3.ENCRYPT
        elif tls_channel_binding:
            ldap_connection_kwargs['channel_binding'] = ldap3.TLS_CHANNEL_BINDING

        try:
            ldap_connection = ldap3.Connection(**ldap_connection_kwargs)
            ldap_connection.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            self._logger.critical(e)
            if self._do_tls:
                self._logger.critical('TLS negociation failed, this error is mostly due to your host '
                                      'not supporting SHA1 as signing algorithm for certificates')
            sys.exit(-1)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            self._logger.warning('Server returns LDAPInvalidCredentialsResult')
            parsed_error_message = self._parse_ldap_invalid_credentials_result_message(ldap_connection.result['message'])
            if parsed_error_message != "SEC_E_BAD_BINDINGS":
                self._logger.critical('Invalid Credentials : {}'.format(parsed_error_message))
                sys.exit(-1)
            # https://github.com/zyn3rgy/LdapRelayScan#ldaps-channel-binding-token-requirements
            elif parsed_error_message == "SEC_E_BAD_BINDINGS" and not self._tls_channel_binding_supported:
                if self._lmhash and self._nthash:
                    self._logger.critical('Server requires Channel Binding Token and your ldap3 install does not support it. '
                                          'Please run "pip install ldap3-bleeding-edge", try another authentication method, '
                                          'or use a password, not a hash, to authenticate.')
                    sys.exit(-1)
                else:
                    self._logger.debug('Server requires Channel Binding Token but you are using password authentication,'
                                       ' falling back to SIMPLE authentication, hoping LDAPS port is open')
                    ldap_server_kwargs = {'host': self._domain_controller, 'formatter': self._formatter,
                                          'get_info': ldap3.ALL, 'use_tls': True}
                    server = ldap3.Server(**ldap_server_kwargs)
                    self._do_simple_auth(server)
                    return
            elif self._tls_channel_binding_supported == True and tls_channel_binding == False:
                self._logger.warning('Falling back to TLS with channel binding')
                self._do_ntlm_auth(server, tls_channel_binding=True)
                return

        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult:
            self._logger.warning('Server returns LDAPStrongerAuthRequiredResult')
            if not self._sign_and_seal_supported:
                self._logger.warning('Sealing not available, falling back to LDAPS')
                # I don't know how to reuse the same Server object, but TLS enabled
                ldap_server_kwargs = {'host': self._domain_controller, 'formatter': self._formatter,
                                      'get_info': ldap3.ALL, 'use_tls': True}
                server = ldap3.Server(**ldap_server_kwargs)
                self._do_ntlm_auth(server)
                return
            else:
                self._logger.warning('Falling back to NTLM sealing')
                self._do_ntlm_auth(server, seal_and_sign=True)
                return

        who_am_i = ldap_connection.extend.standard.who_am_i()
        self._logger.debug('Successfully connected to the LDAP as {}'.format(who_am_i))
        self._ldap_connection = ldap_connection
        self._server_info = server.info

    def _do_kerberos_auth(self, server, seal_and_sign=False):
        self._logger.debug('LDAP authentication with Kerberos: ldap_scheme = {0} / seal_and_sign = {1}'.format(
                            "ldaps" if server.ssl else "ldap", seal_and_sign))
        ldap_connection_kwargs = {"server": server , 'user': '{}@{}'.format(self._user, self._domain.upper()),
                                  'raise_exceptions': True, 'authentication': ldap3.SASL,
                                  'sasl_mechanism': ldap3.KERBEROS}

        if seal_and_sign:
            ldap_connection_kwargs['session_security'] = ldap3.ENCRYPT

        # Verifying if we have the correct TGS/TGT to interrogate the LDAP server
        ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        principal = 'ldap/{}@{}'.format(self._domain_controller.lower(), self._queried_domain.upper())

        # We look for the TGS with the right SPN
        creds = ccache.getCredential(principal, anySPN=False)
        if creds:
            self._logger.debug('TGS found in KRB5CCNAME file')
            creds_server_lower = creds['server'].prettyPrint().lower().decode('utf-8')
            creds_server = creds['server'].prettyPrint().decode('utf-8')
            if creds_server_lower.split('@')[0] != creds_server.split('@')[0]:
                self._logger.debug('SPN not in lowercase, patching SPN')
                new_creds = self._patch_spn(creds, principal)
                # We build a new CCache with the new ticket
                ccache.credentials.append(new_creds)
                temp_ccache = tempfile.NamedTemporaryFile()
                ccache.saveFile(temp_ccache.name)
                cred_store = {'ccache': 'FILE:{}'.format(temp_ccache.name)}
            else:
                self._logger.debug('SPN is good, no patching needed')
                cred_store = dict()
        else:
            self._logger.debug('TGS not found in KRB5CCNAME, looking for '
                    'TGS with alternative SPN')
            # If we don't find it, we search for any SPN
            creds = ccache.getCredential(principal, anySPN=True)
            if creds:
                # If we find one, we build a custom TGS
                self._logger.debug('Alternative TGS found, patching SPN')
                new_creds = self._patch_spn(creds, principal)
                # We build a new CCache with the new ticket
                ccache.credentials.append(new_creds)
                temp_ccache = tempfile.NamedTemporaryFile()
                ccache.saveFile(temp_ccache.name)
                cred_store = {'ccache': 'FILE:{}'.format(temp_ccache.name)}
            else:
                # If we don't find any, we hope for the best (TGT in cache)
                self._logger.debug('Alternative TGS not found, using KRB5CCNAME as is '
                        'while hoping it contains a TGT')
                cred_store = dict()
        ldap_connection_kwargs['cred_store'] = cred_store
        self._logger.debug('LDAP binding parameters: server = {0} / user = {1} '
               '/ Kerberos auth'.format(self._domain_controller, self._user))

        try:
            ldap_connection = ldap3.Connection(**ldap_connection_kwargs)
            ldap_connection.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
                self._logger.critical(e)
                if self._do_tls:
                    self._logger.critical('TLS negociation failed, this error is mostly due to your host '
                                          'not supporting SHA1 as signing algorithm for certificates')
                sys.exit(-1)

        except ldap3.core.exceptions.LDAPStrongerAuthRequiredResult:
            self._logger.warning('Server returns LDAPStrongerAuthRequiredResult')
            if not self._sign_and_seal_supported:
                self._logger.warning('Sealing not available, falling back to LDAPS')
                server.use_ssl = True
                # I don't know how to reuse the same Server object, but switched to TLS
                ldap_server_kwargs = {'host': self._domain_controller, 'formatter': self._formatter,
                                      'get_info': ldap3.ALL, 'use_tls': True}
                server = ldap3.Server(**ldap_server_kwargs)
                self._do_kerberos_auth(server)
                return
            else:
                self._logger.warning('Falling back to Kerberos sealing')
                self._do_kerberos_auth(server, seal_and_sign=True)
                return

        who_am_i = ldap_connection.extend.standard.who_am_i()
        self._logger.debug('Successfully connected to the LDAP as {}'.format(who_am_i))
        self._ldap_connection = ldap_connection
        self._server_info = server.info

    def _do_schannel_auth(self, server):
        self._logger.debug('LDAP authentication with SChannel: ldap_scheme = {0}'.format("ldaps" if server.ssl else "ldap"))
        tls_mode = 'Implicit'
        server.tls = ldap3.Tls(local_private_key_file=self._user_key, local_certificate_file=self._user_cert, validate=ssl.CERT_NONE)
        ldap_connection_kwargs = {'server': server, 'user': None, 'raise_exceptions': True}

        # Explicit TLS, setting up StartTLS
        if not self._do_tls:
            tls_mode = 'Explicit'
            self._logger.warning('Using certificate authentication but --tls not provided, setting up TLS with StartTLS')
            ldap_connection_kwargs['authentication'] = ldap3.SASL
            ldap_connection_kwargs['sasl_mechanism'] = ldap3.EXTERNAL

        self._logger.debug('LDAP binding parameters: server = {0} / cert = {1} '
            '/ key = {2} / {3} TLS / SChannel auth'.format(self._domain_controller, self._user_cert, self._user_key, tls_mode))

        try:
            ldap_connection = ldap3.Connection(**ldap_connection_kwargs)
            ldap_connection.open()
            ldap_connection.raise_exceptions = False
            if not self._do_tls:
                self._logger.debug('Sending StartTLS command')
                if ldap_connection.start_tls():
                    self._logger.debug('StartTLS succeeded')
                    ldap_connection.raise_exceptions = True
                    ldap_connection.bind()
                else:
                    self._logger.critical('StartTLS failed, exiting')
                    sys.exit(-1)
        except Exception as e:
            # I don't really understand exception when using SChannel authentication, but if you see this message
            # your cert and key are probably not valid
            self._logger.critical('Exception during SChannel authentication: {}'.format(e))
            sys.exit(-1)

        who_am_i = ldap_connection.extend.standard.who_am_i()

        if not who_am_i:
            self._logger.critical('Certificate authentication failed')
            sys.exit(-1)

        self._logger.debug('Successfully connected to the LDAP as {}'.format(who_am_i))
        self._ldap_connection = ldap_connection
        self._server_info = server.info

    def _do_simple_auth(self, server):
        self._logger.debug('LDAP authentication with SIMPLE: ldap_scheme = {0}'.format("ldaps" if server.ssl else "ldap"))
        ldap_connection_kwargs = {'server': server, 'user': '{}@{}'.format(self._user, self._domain),
                                  'password': self._password, 'raise_exceptions': True, 'authentication': ldap3.SIMPLE}

        self._logger.debug('LDAP binding parameters: server = {0} / user = {1} '
            '/ password = {2}'.format(self._domain_controller, self._user, self._password))

        try:
            ldap_connection = ldap3.Connection(**ldap_connection_kwargs)
            ldap_connection.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
                self._logger.critical(e)
                if self._do_tls:
                    self._logger.critical('TLS negociation failed, this error is mostly due to your host '
                                          'not supporting SHA1 as signing algorithm for certificates')
                sys.exit(-1)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
            parsed_error_message = self._parse_ldap_invalid_credentials_result_message(ldap_connection.result['message'])
            self._logger.critical('Invalid Credentials : {}'.format(parsed_error_message))
            sys.exit(-1)

        who_am_i = ldap_connection.extend.standard.who_am_i()
        self._logger.debug('Successfully connected to the LDAP as {}'.format(who_am_i))
        self._ldap_connection = ldap_connection
        self._server_info = server.info

    def _get_netfqdn(self):
        server = ldap3.Server(self._domain_controller, get_info=ldap3.ALL)
        connection = ldap3.Connection(server)
        try:
            connection.bind()
            self._logger.debug('retrieved defaultnamingcontext: {}'.format(server.info.other["defaultNamingContext"][0]))
            fqdn = server.info.other["defaultNamingContext"][0][3:].replace(',DC=','.')
        except:
            self._logger.warning('Error when binding anonymously to the LDAP. Retry with -d and -w options.')
            sys.exit(-1)
        self._logger.debug('returned fqdn: {}'.format(fqdn))
        return fqdn

    def _patch_spn(self, creds, principal):
        self._logger.debug('Patching principal to {}'.format(principal))

        from pyasn1.codec.der import decoder, encoder
        from impacket.krb5.asn1 import TGS_REP, Ticket

        # Code is ~~based on~~ stolen from https://github.com/SecureAuthCorp/impacket/pull/1256
        tgs = creds.toTGS(principal)
        decoded_st = decoder.decode(tgs['KDC_REP'], asn1Spec=TGS_REP())[0]
        decoded_st['ticket']['sname']['name-string'][0] = 'ldap'
        decoded_st['ticket']['sname']['name-string'][1] = self._domain_controller.lower()
        decoded_st['ticket']['realm'] = self._queried_domain.upper()

        new_creds = Credential(data=creds.getData())
        new_creds.ticket = CountedOctetString()
        new_creds.ticket['data'] = encoder.encode(decoded_st['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        new_creds.ticket['length'] = len(new_creds.ticket['data'])
        new_creds['server'].fromPrincipal(Principal(principal, type=constants.PrincipalNameType.NT_PRINCIPAL.value))

        return new_creds

    def _create_ldap_connection(self, queried_domain=str(), ads_path=str(),
                                ads_prefix=str()):
        if not queried_domain:
            self._logger.warning('Queried domain not specified, assuming it is the same than the target')
            queried_domain = self._get_netfqdn()

        self._queried_domain = queried_domain

        if not self._domain:
            if self._do_certificate:
                self._logger.critical('-w with the FQDN must be used when authenticating with certificates')
                sys.exit(-1)
            elif self._do_kerberos:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
                self._domain = ccache.principal.realm['data'].decode('utf-8')
            else:
                self._logger.warning('User domain not specified, assuming it is the same than the queried domain')
                self._domain = queried_domain

        ldap_server_kwargs = {'host': self._domain_controller, 'formatter': self._formatter,
                              'get_info': ldap3.ALL}

        if self._do_tls:
            ldap_server_kwargs['use_ssl'] = True
            self._logger.debug('LDAPS connection forced')
        else:
            ldap_server_kwargs['use_ssl'] = False

        ldap_server = ldap3.Server(**ldap_server_kwargs)

        if self._do_kerberos:
            self._do_kerberos_auth(ldap_server)
        elif self._do_certificate:
            self._do_schannel_auth(ldap_server)
        else:
            self._do_ntlm_auth(ldap_server)

        base_dn = str()

        if ads_prefix:
            self._ads_prefix = ads_prefix
            base_dn = '{},'.format(self._ads_prefix)
        if ads_path:
            # TODO: manage ADS path starting with 'GC://'
            if ads_path.upper().startswith('LDAP://'):
                ads_path = ads_path[7:]
            self._ads_path = ads_path
            base_dn += self._ads_path
        else:
            base_dn += self._server_info.other["defaultNamingContext"][0]

        # base_dn is no longer used within `_create_ldap_connection()`, but I don't want to break
        # the function call. So we store it in an attriute and use it in `_ldap_search()`
        self._base_dn = base_dn

    def _ldap_search(self, search_filter, class_result, attributes=list(), controls=list()):
        results = list()

        # if no attribute name specified, we return all attributes
        if not attributes:
            attributes =  ldap3.ALL_ATTRIBUTES

        self._logger.debug('search_base = {0} / search_filter = {1} / attributes = {2}'.format(self._base_dn,
                                                                                               search_filter,
                                                                                               attributes))

        # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
        search_results=self._ldap_connection.extend.standard.paged_search(search_base=self._base_dn,
                search_filter=search_filter, attributes=attributes,
                controls=controls, paged_size=1000, generator=True)

        try:
            # Skip searchResRef
            for result in search_results:
                if result['type'] != 'searchResEntry':
                    continue
                results.append(class_result(result['attributes']))

        except ldap3.core.exceptions.LDAPAttributeError as e:
            self._logger.critical(e)
            sys.exit(-1)

        if not results:
            self._logger.debug('Query returned an empty result')

        return results

    @staticmethod
    def _ldap_connection_init(f):
        def wrapper(*args, **kwargs):
            instance = args[0]
            queried_domain = kwargs.get('queried_domain', None)
            ads_path = kwargs.get('ads_path', None)
            ads_prefix = kwargs.get('ads_prefix', None)
            if (not instance._ldap_connection) or \
               (queried_domain and queried_domain != instance._queried_domain) or \
               (ads_path and ads_path != instance._ads_path) or \
               (ads_prefix and ads_prefix != instance._ads_prefix):
                if instance._ldap_connection:
                    instance._ldap_connection.unbind()
                instance._create_ldap_connection(queried_domain=queried_domain,
                                                 ads_path=ads_path, ads_prefix=ads_prefix)
            return f(*args, **kwargs)
        return wrapper

    def __enter__(self):
        self._create_ldap_connection()
        return self

    def __exit__(self, type, value, traceback):
        try:
            self._ldap_connection.unbind()
        except AttributeError:
            self._logger.warning('Error when unbinding')
            pass
        self._ldap_connection = None

class RPCRequester():
    def __init__(self, target_computer, domain=str(), user=(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False):
        self._target_computer = target_computer
        self._domain = domain
        self._user = user
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._pipe = None
        self._rpc_connection = None
        self._dcom = None
        self._wmi_connection = None

        logger = logging.getLogger('pywerview_main_logger.RPCRequester')
        logger.ULTRA = 5
        self._logger = logger

    def _create_rpc_connection(self, pipe):
        # Here we build the DCE/RPC connection
        self._pipe = pipe

        binding_strings = dict()
        binding_strings['srvsvc'] = srvs.MSRPC_UUID_SRVS
        binding_strings['wkssvc'] = wkst.MSRPC_UUID_WKST
        binding_strings['samr'] = samr.MSRPC_UUID_SAMR
        binding_strings['svcctl'] = scmr.MSRPC_UUID_SCMR
        binding_strings['drsuapi'] = drsuapi.MSRPC_UUID_DRSUAPI

        # TODO: try to fallback to TCP/139 if tcp/445 is closed
        if self._pipe == r'\drsuapi':
            string_binding = epm.hept_map(self._target_computer, drsuapi.MSRPC_UUID_DRSUAPI,
                                          protocol='ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username=self._user, password=self._password,
                                         domain=self._domain, lmhash=self._lmhash,
                                         nthash=self._nthash)
        else:
            rpctransport = transport.SMBTransport(self._target_computer, 445, self._pipe,
                                                  username=self._user, password=self._password,
                                                  domain=self._domain, lmhash=self._lmhash,
                                                  nthash=self._nthash, doKerberos=self._do_kerberos)

        rpctransport.set_connect_timeout(10)
        dce = rpctransport.get_dce_rpc()

        if self._pipe == r'\drsuapi':
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        try:
            dce.connect()
        except Exception as e:
            self._logger.warning('Error when creating RPC connection')
            self._logger.warning(e)
            self._rpc_connection = None
        else:
            dce.bind(binding_strings[self._pipe[1:]])
            self._rpc_connection = dce

    def _create_wmi_connection(self, namespace='root\\cimv2', rpc_auth_level=None):
        self._namespace = namespace
        self._rpc_auth_level = rpc_auth_level

        try:
            self._dcom = DCOMConnection(self._target_computer, self._user, self._password,
                                        self._domain, self._lmhash, self._nthash, doKerberos=self._do_kerberos)
        except Exception as e:
            self._logger.warning('Error when creating WMI connection')
            self._logger.warning(e)
            self._dcom = None
        else:
            i_interface = self._dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                                        wmi.IID_IWbemLevel1Login)
            i_wbem_level1_login = wmi.IWbemLevel1Login(i_interface)
            self._wmi_connection = i_wbem_level1_login.NTLMLogin(ntpath.join('\\\\{}\\'.format(self._target_computer), self._namespace),
                                                                 NULL, NULL)
            if self._rpc_auth_level == 'privacy':
                self._wmi_connection.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            elif self._rpc_auth_level == 'integrity':
                self._wmi_connection.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

    @staticmethod
    def _rpc_connection_init(pipe=r'\srvsvc'):
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if (not instance._rpc_connection) or (pipe != instance._pipe):
                    if instance._rpc_connection:
                        instance._rpc_connection.disconnect()
                    instance._create_rpc_connection(pipe=pipe)
                if instance._rpc_connection is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def _wmi_connection_init(namespace='root\\cimv2', rpc_auth_level=None):
        def decorator(f):
            def wrapper(*args, **kwargs):
                instance = args[0]
                if (not instance._wmi_connection) or (namespace != instance._namespace) \
                        or (rpc_auth_level != instance._rpc_auth_level):
                    instance._create_wmi_connection()
                if instance._dcom is None:
                    return None
                return f(*args, **kwargs)
            return wrapper
        return decorator

    def __enter__(self):
        # Picked because it's the most used by the net* functions
        self._create_rpc_connection(r'\srvsvc')
        return self

    def __exit__(self, type, value, traceback):
        try:
            self._rpc_connection.disconnect()
        except AttributeError:
            pass
        self._rpc_connection = None

class LDAPRPCRequester(LDAPRequester, RPCRequester):
    def __init__(self, target_computer, domain=str(), user=str(), password=str(),
                 lmhash=str(), nthash=str(), do_kerberos=False, do_tls=False,
                 user_cert=str(), user_key=str(), domain_controller=str()):
        # If no domain controller was given, we assume that the user wants to
        # target a domain controller to perform LDAP requests against
        if not domain_controller:
            domain_controller = target_computer

        LDAPRequester.__init__(self, domain_controller, domain, user, password,
                               lmhash, nthash, do_kerberos, do_tls,
                               user_cert, user_key)

        if user_cert is not None and user_key is not None:
            RPCRequester.__init__(self, target_computer, domain, user, password,
                                  lmhash, nthash, do_kerberos)

        logger = logging.getLogger('pywerview_main_logger.LDAPRPCRequester')
        logger.ULTRA = 5
        self._logger = logger

    def __enter__(self):
        try:
            LDAPRequester.__enter__(self)
        except (socket.error, IndexError):
            pass

        try:
            RPCRequester.__enter__(self)
        except (AttributeError):
            pass

        return self

    def __exit__(self, type, value, traceback):
        LDAPRequester.__exit__(self, type, value, traceback)
        RPCRequester.__exit__(self, type, value, traceback)

