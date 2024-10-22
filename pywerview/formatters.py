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

import logging
import binascii

try:
    from Cryptodome.Hash import MD4
except ImportError:
    from Crypto.Hash import MD4

from impacket.examples.ntlmrelayx.attacks.ldapattack import MSDS_MANAGEDPASSWORD_BLOB
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

__uac_flags = {0x0000001: 'SCRIPT',
               0x0000002: 'ACCOUNTDISABLE',
               0x0000008: 'HOMEDIR_REQUIRED',
               0x0000010: 'LOCKOUT',
               0x0000020: 'PASSWD_NOTREQD',
               0x0000040: 'PASSWD_CANT_CHANGE',
               0x0000080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
               0x0000100: 'TEMP_DUPLICATE_ACCOUNT',
               0x0000200: 'NORMAL_ACCOUNT',
               0x0000800: 'INTERDOMAIN_TRUST_ACCOUNT',
               0x0001000: 'WORKSTATION_TRUST_ACCOUNT',
               0x0002000: 'SERVER_TRUST_ACCOUNT',
               0x0010000: 'DONT_EXPIRE_PASSWORD',
               0x0020000: 'MNS_LOGON_ACCOUNT',
               0x0040000: 'SMARTCARD_REQUIRED',
               0x0080000: 'TRUSTED_FOR_DELEGATION',
               0x0100000: 'NOT_DELEGATED',
               0x0200000: 'USE_DES_KEY_ONLY',
               0x0400000: 'DONT_REQ_PREAUTH',
               0x0800000: 'PASSWORD_EXPIRED',
               0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
               0x4000000: 'PARTIAL_SECRETS_ACCOUNT'}

__sat_flags = {0x00000000: 'DOMAIN_OBJECT',
               0x10000000: 'GROUP_OBJECT',
               0x10000001: 'NON_SECURITY_GROUP_OBJECT',
               0x20000000: 'ALIAS_OBJECT',
               0x20000001: 'NON_SECURITY_ALIAS_OBJECT',
               # According to https://docs.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
               # USER_OBJECT and NORMAL_USER_ACCOUNT are both 0x30000000
               0x30000000: 'USER_OBJECT',
               0x30000001: 'MACHINE_ACCOUNT',
               0x30000002: 'TRUST_ACCOUNT',
               0x40000000: 'APP_BASIC_GROUP',
               0x40000001: 'APP_QUERY_GROUP',
               0x7fffffff: 'ACCOUNT_TYPE_MAX'}

__ace_flags = {0x1: 'object_inherit', 0x2: 'container_inherit',
               0x4: 'non_propagate_inherit', 0x8: 'inherit_only',
               0x10: 'inherited_ace', 0x20: 'audit_successful_accesses',
               0x40: 'audit_failed_access'}

__object_ace_flags = {0x1: 'object_ace_type_present', 0x2: 'inherited_object_ace_type_present'}

# Resources: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
__access_mask = {0x1: 'create_child', 0x2: 'delete_child',
                 0x4: 'list_children', 0x08: 'self',
                 0x10: 'read_property', 0x20: 'write_property',
                 0x40: 'delete_tree', 0x80: 'list_object',
                 0x100: 'extended_right', 0x10000: 'delete',
                 0x20000: 'read_control', 0x40000: 'write_dacl',
                 0x80000: 'write_owner'}

__access_mask_generic = {0xf01ff: 'generic_all', 0x20094: 'generic_read',
                         0x20028: 'generic_write', 0x20004: 'generic_execute'}

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
__trust_attrib = {0x1: 'TRUST_ATTRIBUTE_NON_TRANSITIVE', 
                  0x2: 'TRUST_ATTRIBUTE_UPLEVEL_ONLY',
                  0x4: 'TRUST_ATTRIBUTE_QUARANTINED_DOMAIN', 
                  0x8: 'TRUST_ATTRIBUTE_FOREST_TRANSITIVE',
                  0x10: 'TRUST_ATTRIBUTE_CROSS_ORGANIZATION', 
                  0x20: 'TRUST_ATTRIBUTE_WITHIN_FOREST',
                  0x40: 'TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL',
                  0x80: 'TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION',
                  # TODO: x100 seems not documented ?
                  0x100: 'TRUST_USES_AES_KEYS',
                  0X200: 'TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION',
                  0x400: 'TRUST_ATTRIBUTE_PIM_TRUST',
                  0x800: 'TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION'}

__trust_direction = {0: 'disabled', 1: 'inbound',
                     2: 'outbound', 3: 'bidirectional'}

__trust_type = {1: 'windows_non_active_directory',
                2: 'windows_active_directory', 3: 'mit'}

# https://www.pkisolutions.com/object-identifiers-oid-in-pki/
# sources: Certipy/certipy/lib/constants.py
__ekus = {
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security use",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.23.133.8.2": "Platform Certificate",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1": "Server Trust",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
}

__mspki_enrollment_flag = {
    0x00000001 : "INCLUDE_SYMMETRIC_ALGORITHMS",
    0x00000002 : "PEND_ALL_REQUESTS",
    0x00000004 : "PUBLISH_TO_KRA_CONTAINER",
    0x00000008 : "PUBLISH_TO_DS",
    0x00000010 : "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    0x00000020 : "AUTO_ENROLLMENT",
    0x00000080 : "CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED",
    0x00000040 : "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    0x00000100 : "USER_INTERACTION_REQUIRED",
    0x00000200 : "ADD_TEMPLATE_NAME",
    0x00000400 : "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    0x00000800 : "ALLOW_ENROLL_ON_BEHALF_OF",
    0x00001000 : "ADD_OCSP_NOCHECK",
    0x00002000 : "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    0x00004000 : "NOREVOCATIONINFOINISSUEDCERTS",
    0x00008000 : "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    0x00010000 : "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
    0x00020000 : "ISSUANCE_POLICIES_FROM_REQUEST",
    0x00040000 : "SKIP_AUTO_RENEWAL",
    0x00080000 : "NO_SECURITY_EXTENSION"
}

def __format_flag(raw_value, flag_dict):
    try:
        int_value = int(raw_value)
    except ValueError:
        return raw_value

    parsed_flags = list()
    for flag, flag_label in flag_dict.items():
        if (int_value & flag) == flag:
            parsed_flags.append(flag_label)
    return parsed_flags

def __format_dict_lookup(raw_value, dictionary):
    try:
        return dictionary[int(raw_value)]
    except (ValueError, KeyError):
        return raw_value

def format_useraccountcontrol(raw_value):
    return __format_flag(raw_value, __uac_flags)

def format_samaccounttype(raw_value):
    return __sat_flags[int(raw_value)]

def format_ace_access_mask(raw_value):
    try:
        int_value = int(raw_value)
    except ValueError:
        return raw_value

    activedirectoryrights = list()
    for flag, flag_label in __access_mask_generic.items():
        if (int_value & flag) == flag:
            activedirectoryrights.append(flag_label)
            int_value ^= flag
    activedirectoryrights += __format_flag(raw_value, __access_mask)

    return activedirectoryrights


def format_managedpassword(raw_value):
    blob = MSDS_MANAGEDPASSWORD_BLOB()
    blob.fromString(raw_value)
    return binascii.hexlify(MD4.new(blob['CurrentPassword'][:-2]).digest()).decode('utf8')

def format_groupmsamembership(raw_value):
    sid = list()
    sr = SR_SECURITY_DESCRIPTOR(data=raw_value)
    for dacl in sr['Dacl']['Data']:
        sid.append(dacl['Ace']['Sid'].formatCanonical())
    return sid

def format_ace_flags(raw_value):
    return __format_flag(raw_value, __ace_flags)

def format_object_ace_flags(raw_value):
    return __format_flag(raw_value, __object_ace_flags)

def format_trustdirection(raw_value):
    return __format_dict_lookup(raw_value, __trust_direction)

def format_trusttype(raw_value):
    return __format_dict_lookup(raw_value, __trust_type)

def format_trustattributes(raw_value):
    return __format_flag(raw_value, __trust_attrib)

def format_ekus(raw_value):
    raw_value = raw_value.decode('utf-8')
    try:
        return __ekus[raw_value]
    except KeyError:
        return raw_value

def format_mspkienrollmentflag(raw_value):
    return __format_flag(raw_value, __mspki_enrollment_flag)
