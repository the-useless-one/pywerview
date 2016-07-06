#!/usr/bin/env python
# -*- coding: utf8 -*-
#
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

import argparse
from pywerview.net import *
from pywerview.gpo import *
from pywerview.misc import *

if __name__ == '__main__':
    # Main parser
    parser = argparse.ArgumentParser(description='Rewriting of some PowerView\'s functionalities in Python')
    subparsers = parser.add_subparsers(title='Subcommands', description='Available subcommands')

    # TODO: support keberos authentication
    # Credentials parser
    credentials_parser = argparse.ArgumentParser(add_help=False)
    credentials_parser.add_argument('-w', '--workgroup', dest='domain',
            default=str(), help='Name of the domain we authenticate with')
    credentials_parser.add_argument('-u', '--user', required=True,
            help='Username used to connect to the Domain Controller')
    credentials_parser.add_argument('-p', '--password',
            help='Password associated to the username')
    credentials_parser.add_argument('--hashes', action='store', metavar = 'LMHASH:NTHASH',
            help='NTLM hashes, format is LMHASH:NTHASH')

    # AD parser, used for net* functions running against a domain controller
    ad_parser = argparse.ArgumentParser(add_help=False, parents=[credentials_parser])
    ad_parser.add_argument('-t', '--dc-ip', dest='domain_controller',
            required=True, help='IP address of the Domain Controller to target')

    # Parser for the get-adobject command
    get_adobject_parser= subparsers.add_parser('get-adobject', help='Takes a domain SID, '\
        'samAccountName or name, and return the associated object', parents=[ad_parser])
    get_adobject_parser.add_argument('--sid', dest='queried_sid',
            help='SID to query (wildcards accepted)')
    get_adobject_parser.add_argument('--sam-account-name', dest='queried_sam_account_name',
            help='samAccountName to query (wildcards accepted)')
    get_adobject_parser.add_argument('--name', dest='queried_name',
            help='Name to query (wildcards accepted)')
    get_adobject_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_adobject_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_adobject_parser.set_defaults(func=get_adobject)
    
    # Parser for the get-netuser command
    get_netuser_parser= subparsers.add_parser('get-netuser', help='Queries information about '\
        'a domain user', parents=[ad_parser])
    get_netuser_parser.add_argument('--username', dest='queried_username',
            help='Username to query (wildcards accepted)')
    get_netuser_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netuser_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_netuser_parser.add_argument('--unconstrained', action='store_true',
            help='Query only users with unconstrained delegation')
    get_netuser_parser.add_argument('--admin-count', action='store_true',
            help='Query only users with adminCount=1')
    get_netuser_parser.add_argument('--allow-delegation', action='store_true',
            help='Return user accounts that are not marked as \'sensitive and not allowed for delegation\'')
    get_netuser_parser.add_argument('--spn', action='store_true',
            help='Query only users with not-null Service Principal Names')
    get_netuser_parser.set_defaults(func=get_netuser)
    
    # Parser for the get-netgroup command
    get_netgroup_parser= subparsers.add_parser('get-netgroup', help='Get a list of all current '\
        'domain groups, or a list of groups a domain user is member of', parents=[ad_parser])
    get_netgroup_parser.add_argument('--groupname', dest='queried_groupname',
            default='*', help='Group to query (wildcards accepted)')
    get_netgroup_parser.add_argument('--sid', dest='queried_sid',
            help='Group SID to query')
    get_netgroup_parser.add_argument('--username', dest='queried_username',
            help='Username to query: will list the groups this user is a member of (wildcards accepted)')
    get_netgroup_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netgroup_parser.add_argument('-a', '--ads-path', dest='ads_path',
            help='Additional ADS path')
    get_netgroup_parser.add_argument('--full-data', action='store_true',
            help='If set, returns full information on the groups, otherwise, just the samAccountName')
    get_netgroup_parser.add_argument('--admin-count', action='store_true',
            help='Query only users with adminCount=1')
    get_netgroup_parser.set_defaults(func=get_netgroup)
    
    # Parser for the get-netcomputer command
    get_netcomputer_parser= subparsers.add_parser('get-netcomputer', help='Queries informations about '\
        'domain computers', parents=[ad_parser])
    get_netcomputer_parser.add_argument('--computername', dest='queried_computername',
            default='*', help='Computer name to query')
    get_netcomputer_parser.add_argument('-os', '--operating-system', dest='queried_os',
            help='Return computers with a specific operating system (wildcards accepted)')
    get_netcomputer_parser.add_argument('-sp', '--service-pack', dest='queried_sp',
            help='Return computers with a specific service pack (wildcards accepted)')
    get_netcomputer_parser.add_argument('-spn', '--service-principal-name', dest='queried_spn',
            help='Return computers with a specific service principal name (wildcards accepted)')
    get_netcomputer_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netcomputer_parser.add_argument('-a', '--ads-path', dest='ads_path',
            help='Additional ADS path')
    get_netcomputer_parser.add_argument('--printers', action='store_true',
            help='Query only printers')
    get_netcomputer_parser.add_argument('--unconstrained', action='store_true',
            help='Query only computers with unconstrained delegation')
    get_netcomputer_parser.add_argument('--ping', action='store_true',
            help='Ping computers (will only return up computers)')
    get_netcomputer_parser.add_argument('--full-data', action='store_true',
            help='If set, returns full information on the groups, otherwise, just the dnsHostName')
    get_netcomputer_parser.set_defaults(func=get_netcomputer)
    
    # Parser for the get-netdomaincontroller command
    get_netdomaincontroller_parser= subparsers.add_parser('get-netdomaincontroller', help='Get a list of '\
        'domain controllers for the given domain', parents=[ad_parser])
    get_netdomaincontroller_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netdomaincontroller_parser.set_defaults(func=get_netdomaincontroller)
    
    # Parser for the get-netfileserver command
    get_adobject_parser= subparsers.add_parser('get-netfileserver', help='Return a list of '\
        'file servers, extracted from the domain users\' homeDirectory, scriptPath, and profilePath fields', parents=[ad_parser])
    get_adobject_parser.add_argument('--target-users', nargs='+',
            metavar='TARGET_USER', help='A list of users to target to find file servers (wildcards accepted)')
    get_adobject_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_adobject_parser.set_defaults(func=get_netfileserver)

    # Parser for the get-netou command
    get_netou_parser= subparsers.add_parser('get-netou', help='Get a list of all current '\
        'OUs in the domain', parents=[ad_parser])
    get_netou_parser.add_argument('--ouname', dest='queried_ouname',
            default='*', help='OU name to query (wildcards accepted)')
    get_netou_parser.add_argument('--guid', dest='queried_guid',
            help='Only return OUs with the specified GUID in their gplink property.')
    get_netou_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netou_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_netou_parser.add_argument('--full-data', action='store_true',
            help='If set, returns full information on the OUs, otherwise, just the adspath')
    get_netou_parser.set_defaults(func=get_netou)
    
    # Parser for the get-netsite command
    get_netsite_parser= subparsers.add_parser('get-netsite', help='Get a list of all current '\
        'sites in the domain', parents=[ad_parser])
    get_netsite_parser.add_argument('--sitename', dest='queried_sitename',
            help='Site name to query (wildcards accepted)')
    get_netsite_parser.add_argument('--guid', dest='queried_guid',
            help='Only return sites with the specified GUID in their gplink property.')
    get_netsite_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netsite_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_netsite_parser.add_argument('--full-data', action='store_true',
            help='If set, returns full information on the sites, otherwise, just the name')
    get_netsite_parser.set_defaults(func=get_netsite)
    
    # Parser for the get-netsubnet command
    get_netsubnet_parser= subparsers.add_parser('get-netsubnet', help='Get a list of all current '\
        'subnets in the domain', parents=[ad_parser])
    get_netsubnet_parser.add_argument('--sitename', dest='queried_sitename',
            help='Only return subnets for the specified site name (wildcards accepted)')
    get_netsubnet_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netsubnet_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_netsubnet_parser.add_argument('--full-data', action='store_true',
            help='If set, returns full information on the subnets, otherwise, just the name')
    get_netsubnet_parser.set_defaults(func=get_netsubnet)
    
    # Parser for the get-netgpo command
    get_netgpo_parser= subparsers.add_parser('get-netgpo', help='Get a list of all current '\
        'GPOs in the domain', parents=[ad_parser])
    get_netgpo_parser.add_argument('--gponame', dest='queried_gponame',
            default='*', help='GPO name to query for (wildcards accepted)')
    get_netgpo_parser.add_argument('--displayname', dest='queried_displayname',
            help='Display name to query for (wildcards accepted)')
    get_netgpo_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netgpo_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_netgpo_parser.set_defaults(func=get_netgpo)
    
    # Parser for the get-netgroup command
    get_netgroupmember_parser= subparsers.add_parser('get-netgroupmember', help='Return a list of members of a domain groups', parents=[ad_parser])
    get_netgroupmember_parser.add_argument('--groupname', dest='queried_groupname',
            help='Group to query, defaults to the \'Domain Admins\' group (wildcards accepted)')
    get_netgroupmember_parser.add_argument('--sid', dest='queried_sid',
            help='SID to query')
    get_netgroupmember_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netgroupmember_parser.add_argument('-a', '--ads-path', dest='ads_path',
            help='Additional ADS path')
    get_netgroupmember_parser.add_argument('-r', '--recurse', action='store_true',
            help='If the group member is a group, try to resolve its members as well')
    get_netgroupmember_parser.add_argument('--use-matching-rule', action='store_true',
            help='Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query when -Recurse is specified.\n' \
        'Much faster than manual recursion, but doesn\'t reveal cross-domain groups')
    get_netgroupmember_parser.add_argument('--full-data', action='store_true',
            help='If set, returns full information on the members')
    get_netgroupmember_parser.set_defaults(func=get_netgroupmember)

    # Parser for the get-netsession command
    get_netsession_parser= subparsers.add_parser('get-netsession', help='Queries a host to return a '\
        'list of active sessions on the host (you can use local credentials instead of domain credentials)', parents=[credentials_parser])
    get_netsession_parser.add_argument('--computername', dest='target_computername',
            help='Computer to list sessions on')
    get_netsession_parser.set_defaults(func=get_netsession)

    # Parser for the get-netshare command
    get_netshare_parser= subparsers.add_parser('get-netshare', help='Queries a host to return a '\
        'list of available shares on the host (you can use local credentials instead of domain credentials)', parents=[credentials_parser])
    get_netshare_parser.add_argument('--computername', dest='target_computername',
            help='Computer to list shares on')
    get_netshare_parser.set_defaults(func=get_netshare)

    # Parser for the get-netloggedon command
    get_netloggedon_parser= subparsers.add_parser('get-netloggedon', help='This function will '\
        'execute the NetWkstaUserEnum RPC call ti query a given host for actively logged on '\
        'users', parents=[credentials_parser])
    get_netloggedon_parser.add_argument('--computername', dest='target_computername',
            help='Computer to list logged on users on')
    get_netloggedon_parser.set_defaults(func=get_netloggedon)

    # Parser for the get-netlocalgroup command
    get_netlocalgroup_parser= subparsers.add_parser('get-netlocalgroup', help='Gets a list of '\
        'members of a local group on a machine, or returns every local group. You can use local '\
        'credentials instead of domain credentials, however, domain credentials are needed to '\
        'resolve domain SIDs.', parents=[credentials_parser])
    get_netlocalgroup_parser.add_argument('--computername', dest='target_computername',
            help='Computer to list the local groups on')
    get_netlocalgroup_parser.add_argument('--groupname', dest='queried_groupname',
            help='Group to list the members of (defaults to the local \'Administrators\' group')
    get_netlocalgroup_parser.add_argument('--list-groups', action='store_true',
            help='If set, returns a list of the local groups on the targets')
    get_netlocalgroup_parser.add_argument('-t', '--dc-ip', dest='domain_controller',
            default=str(), help='IP address of the Domain Controller (used to resolve domain SIDs)')
    get_netlocalgroup_parser.add_argument('-r', '--recurse', action='store_true',
            help='If the group member is a domain group, try to resolve its members as well')
    get_netlocalgroup_parser.set_defaults(func=get_netlocalgroup)

    # Parser for the invoke-checklocaladminaccess command
    invoke_checklocaladminaccess_parser = subparsers.add_parser('invoke-checklocaladminaccess', help='Checks '\
            'if the given user has local admin acces on the given host', parents=[credentials_parser])
    invoke_checklocaladminaccess_parser.add_argument('--computername', dest='target_computername',
            help='Computer to test local admin access on')
    invoke_checklocaladminaccess_parser.set_defaults(func=invoke_checklocaladminaccess)

    args = parser.parse_args()
    if args.hashes:
        args.lmhash, args.nthash = args.hashes.split(':')
    else:
        args.lmhash = args.nthash = str()

    if not args.password and not args.hashes:
        from getpass import getpass
        password = getpass('Password:')

    parsed_args = dict()
    for k, v in vars(args).iteritems():
        if k not in ('func', 'hashes'):
            parsed_args[k] = v

    #try:
    results = args.func(**parsed_args)
    #except Exception, e:
        #print >>sys.stderr, repr(e)
        #sys.exit(-1)

    try:
        print '\n\n'.join(str(x) for x in results)
    except TypeError:
        print results

