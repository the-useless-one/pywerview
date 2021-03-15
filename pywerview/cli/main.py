#!/usr/bin/env python3
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

# Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2021

import argparse
from pywerview.cli.helpers import *
from pywerview.functions.hunting import *

def main():
    # Main parser
    parser = argparse.ArgumentParser(description='Rewriting of some PowerView\'s functionalities in Python')
    subparsers = parser.add_subparsers(title='Subcommands', description='Available subcommands', dest='submodule')
    
    # hack for python < 3.9 : https://stackoverflow.com/questions/23349349/argparse-with-required-subparser
    subparsers.required = True

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
            help='NTLM hashes, format is [LMHASH:]NTHASH')

    # AD parser, used for net* functions running against a domain controller
    ad_parser = argparse.ArgumentParser(add_help=False, parents=[credentials_parser])
    ad_parser.add_argument('-t', '--dc-ip', dest='domain_controller',
            required=True, help='IP address of the Domain Controller to target')

    # Target parser, used for net* functions running against a normal computer
    target_parser = argparse.ArgumentParser(add_help=False, parents=[credentials_parser])
    target_parser.add_argument('--computername', dest='target_computername',
            required=True, help='IP address of the computer target')

    # Hunter parser, used for hunting functions
    hunter_parser = argparse.ArgumentParser(add_help=False)
    hunter_parser.add_argument('--computername', dest='queried_computername',
            nargs='+', default=list(), help='Host to enumerate against')
    hunter_parser.add_argument('--computerfile', dest='queried_computerfile',
            type=argparse.FileType('r'), help='File of hostnames/IPs to search')
    hunter_parser.add_argument('--computer-filter', dest='queried_computerfilter',
            type=str, default=str(), help='Custom filter used to search computers against the DC')
    hunter_parser.add_argument('--computer-adspath', dest='queried_computeradspath',
            type=str, default=str(), help='ADS path used to search computers against the DC')
    hunter_parser.add_argument('--groupname', dest='queried_groupname',
            help='Group name to query for target users')
    hunter_parser.add_argument('--targetserver', dest='target_server',
            help='Hunt for users who are effective local admins on this target server')
    hunter_parser.add_argument('--username', dest='queried_username',
            help='Hunt for a specific user name')
    hunter_parser.add_argument('--user-filter', dest='queried_userfilter',
            type=str, default=str(), help='Custom filter used to search users against the DC')
    hunter_parser.add_argument('--user-adspath', dest='queried_useradspath',
            type=str, default=str(), help='ADS path used to search users against the DC')
    hunter_parser.add_argument('--userfile', dest='queried_userfile',
            type=argparse.FileType('r'), help='File of user names to target')
    hunter_parser.add_argument('--threads', type=int,
            default=1, help='Number of threads to use (default: %(default)s)')
    hunter_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query for machines')

    # Parser for the get-adobject command
    get_adobject_parser = subparsers.add_parser('get-adobject', help='Takes a domain SID, '\
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
    get_netuser_parser = subparsers.add_parser('get-netuser', help='Queries information about '\
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
    get_netuser_parser.add_argument('--preauth-notreq', action='store_true',
            help='Search for users with the PREAUTH_NOT_REQUIRED account control')
    get_netuser_parser.add_argument('--spn', action='store_true',
            help='Query only users with not-null Service Principal Names')
    get_netuser_parser.add_argument('--custom-filter', dest='custom_filter',
            default=str(), help='Custom filter')
    get_netuser_parser.add_argument('--attributes', nargs='+', dest='attributes',
            default=[], help='Object attributes to return')
    get_netuser_parser.set_defaults(func=get_netuser)

    # Parser for the get-netgroup command
    get_netgroup_parser = subparsers.add_parser('get-netgroup', help='Get a list of all current '\
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
    get_netcomputer_parser = subparsers.add_parser('get-netcomputer', help='Queries informations about '\
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
    get_netcomputer_parser.add_argument('--attributes', nargs='+', dest='attributes',
            default=[], help='Object attributes to return')
    get_netcomputer_parser.set_defaults(func=get_netcomputer)

    # Parser for the get-netdomaincontroller command
    get_netdomaincontroller_parser = subparsers.add_parser('get-netdomaincontroller', help='Get a list of '\
        'domain controllers for the given domain', parents=[ad_parser])
    get_netdomaincontroller_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netdomaincontroller_parser.set_defaults(func=get_netdomaincontroller)

    # Parser for the get-netfileserver command
    get_netfileserver_parser = subparsers.add_parser('get-netfileserver', help='Return a list of '\
        'file servers, extracted from the domain users\' homeDirectory, scriptPath, and profilePath fields', parents=[ad_parser])
    get_netfileserver_parser.add_argument('--target-users', nargs='+',
            metavar='TARGET_USER', help='A list of users to target to find file servers (wildcards accepted)')
    get_netfileserver_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netfileserver_parser.set_defaults(func=get_netfileserver)

    # Parser for the get-dfsshare command
    get_dfsshare_parser = subparsers.add_parser('get-dfsshare', help='Return a list of '\
        'all fault tolerant distributed file systems for a given domain', parents=[ad_parser])
    get_dfsshare_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_dfsshare_parser.add_argument('-v', '--version', nargs='+', choices=['v1', 'v2'],
            default=['v1', 'v2'], help='The version of DFS to query for servers: v1, v2 or all (default: all)')
    get_dfsshare_parser.add_argument('-a', '--ads-path', dest='ads_path',
            help='Additional ADS path')
    get_dfsshare_parser.set_defaults(func=get_dfsshare)

    # Parser for the get-netou command
    get_netou_parser = subparsers.add_parser('get-netou', help='Get a list of all current '\
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
    get_netsite_parser = subparsers.add_parser('get-netsite', help='Get a list of all current '\
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
    get_netsubnet_parser = subparsers.add_parser('get-netsubnet', help='Get a list of all current '\
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

    # Parser for the get-netdomaintrust command
    get_netdomaintrust_parser = subparsers.add_parser('get-netdomaintrust', help='Returns a list of all the '\
        'trusts of the specified domain', parents=[ad_parser])
    get_netdomaintrust_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netdomaintrust_parser.set_defaults(func=get_netdomaintrust)

    # Parser for the get-netgpo command
    get_netgpo_parser = subparsers.add_parser('get-netgpo', help='Get a list of all current '\
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

    # Parser for the get-domainpolicy command
    get_domainpolicy_parser = subparsers.add_parser('get-domainpolicy', help='Returns the default domain or DC '\
        'policy for the queried domain or DC', parents=[ad_parser])
    get_domainpolicy_parser.add_argument('--source', dest='source', default='domain',
            choices=['domain', 'dc'], help='Extract domain or DC policy (default: %(default)s)')
    get_domainpolicy_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_domainpolicy_parser.add_argument('--resolve-sids', dest='resolve_sids',
            action='store_true', help='Resolve SIDs when querying a DC policy')
    get_domainpolicy_parser.set_defaults(func=get_domainpolicy)

    # Parser for the get-gpttmpl command
    get_gpttmpl_parser = subparsers.add_parser('get-gpttmpl', help='Helper to parse a GptTmpl.inf policy '\
            'file path into a custom object', parents=[ad_parser])
    get_gpttmpl_parser.add_argument('--gpt-tmpl-path', type=str, required=True,
            dest='gpttmpl_path', help='The GptTmpl.inf file path name to parse')
    get_gpttmpl_parser.set_defaults(func=get_gpttmpl)

    # Parser for the get-netgpogroup command
    get_netgpogroup_parser = subparsers.add_parser('get-netgpogroup', help='Parses all GPOs in the domain '\
        'that set "Restricted Group" or "Groups.xml"', parents=[ad_parser])
    get_netgpogroup_parser.add_argument('--gponame', dest='queried_gponame',
            default='*', help='GPO name to query for (wildcards accepted)')
    get_netgpogroup_parser.add_argument('--displayname', dest='queried_displayname',
            help='Display name to query for (wildcards accepted)')
    get_netgpogroup_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    get_netgpogroup_parser.add_argument('-a', '--ads-path',
            help='Additional ADS path')
    get_netgpogroup_parser.add_argument('--resolve-sids', dest='resolve_sids',
            action='store_true', help='Resolve SIDs of the members and the target groups')
    get_netgpogroup_parser.set_defaults(func=get_netgpogroup)

    # Parser for the find-gpocomputeradmin command
    find_gpocomputeradmin_parser = subparsers.add_parser('find-gpocomputeradmin', help='Takes a computer (or OU) and determine '\
        'who has administrative access to it via GPO', parents=[ad_parser])
    find_gpocomputeradmin_parser.add_argument('--computername', dest='queried_computername',
            default=str(), help='The computer to determine who has administrative access to it')
    find_gpocomputeradmin_parser.add_argument('--ouname', dest='queried_ouname',
            default=str(), help='OU name to determine who has administrative access to computers within it')
    find_gpocomputeradmin_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    find_gpocomputeradmin_parser.add_argument('-r', '--recurse', dest='recurse',
            action='store_true', help='If one of the returned members is a group, '\
                    'recurse and get all members')
    find_gpocomputeradmin_parser.set_defaults(func=find_gpocomputeradmin)

    # Parser for the find-gpolocation command
    find_gpolocation_parser = subparsers.add_parser('find-gpolocation', help='Takes a username or a group name and determine '\
        'the computers it has administrative access to via GPO', parents=[ad_parser])
    find_gpolocation_parser.add_argument('--username', dest='queried_username',
            default=str(), help='The username to query for access (no wildcard)')
    find_gpolocation_parser.add_argument('--groupname', dest='queried_groupname',
            default=str(), help='The group name to query for access (no wildcard)')
    find_gpolocation_parser.add_argument('-d', '--domain', dest='queried_domain',
            help='Domain to query')
    find_gpolocation_parser.add_argument('--local-group', dest='queried_localgroup',
            default='S-1-5-32-544', help='The local group to check access against. It can be ' \
                    '\'Administrators\', \'RDP\', or a \'S-1-5-X\' SID type')
    find_gpolocation_parser.set_defaults(func=find_gpolocation)

    # Parser for the get-netgroup command
    get_netgroupmember_parser = subparsers.add_parser('get-netgroupmember', help='Return a list of members of a domain group', parents=[ad_parser])
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
    get_netsession_parser = subparsers.add_parser('get-netsession', help='Queries a host to return a '\
        'list of active sessions on the host (you can use local credentials instead of domain credentials)', parents=[target_parser])
    get_netsession_parser.set_defaults(func=get_netsession)

    #Parser for the get-localdisks command
    get_localdisks_parser = subparsers.add_parser('get-localdisks', help='Queries a host to return a '\
        'list of active disks on the host (you can use local credentials instead of domain credentials)', parents=[target_parser])
    get_localdisks_parser.set_defaults(func=get_localdisks)

    #Parser for the get-netdomain command
    get_netdomain_parser = subparsers.add_parser('get-netdomain', help='Queries a host for available domains',
        parents=[ad_parser])
    get_netdomain_parser.set_defaults(func=get_netdomain)

    # Parser for the get-netshare command
    get_netshare_parser = subparsers.add_parser('get-netshare', help='Queries a host to return a '\
        'list of available shares on the host (you can use local credentials instead of domain credentials)', parents=[target_parser])
    get_netshare_parser.set_defaults(func=get_netshare)

    # Parser for the get-netloggedon command
    get_netloggedon_parser = subparsers.add_parser('get-netloggedon', help='This function will '\
        'execute the NetWkstaUserEnum RPC call to query a given host for actively logged on '\
        'users', parents=[target_parser])
    get_netloggedon_parser.set_defaults(func=get_netloggedon)

    # Parser for the get-netlocalgroup command
    get_netlocalgroup_parser = subparsers.add_parser('get-netlocalgroup', help='Gets a list of '\
        'members of a local group on a machine, or returns every local group. You can use local '\
        'credentials instead of domain credentials, however, domain credentials are needed to '\
        'resolve domain SIDs.', parents=[target_parser])
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
            'if the given user has local admin access on the given host', parents=[target_parser])
    invoke_checklocaladminaccess_parser.set_defaults(func=invoke_checklocaladminaccess)

    # Parser for the get-netprocess command
    get_netprocess_parser = subparsers.add_parser('get-netprocess', help='This function will '\
        'execute the \'Select * from Win32_Process\' WMI query to a given host for a list of '\
        'executed process', parents=[target_parser])
    get_netprocess_parser.set_defaults(func=get_netprocess)

    # Parser for the get-userevent command
    get_userevent_parser = subparsers.add_parser('get-userevent', help='This function will '\
        'execute the \'Select * from Win32_Process\' WMI query to a given host for a list of '\
        'executed process', parents=[target_parser])
    get_userevent_parser.add_argument('--event-type', nargs='+', choices=['logon', 'tgt'],
            default=['logon', 'tgt'], help='The type of event to search for: logon, tgt, or all (default: all)')
    get_userevent_parser.add_argument('--date-start', type=int,
            default=5, help='(Filter out events before this date (in days) default: %(default)s)')
    get_userevent_parser.set_defaults(func=get_userevent)

    # Parser for the invoke-userhunter command
    invoke_userhunter_parser = subparsers.add_parser('invoke-userhunter', help='Finds '\
            'which machines domain users are logged into', parents=[ad_parser, hunter_parser])
    invoke_userhunter_parser.add_argument('--unconstrained', action='store_true',
            help='Query only computers with unconstrained delegation')
    invoke_userhunter_parser.add_argument('--admin-count', action='store_true',
            help='Query only users with adminCount=1')
    invoke_userhunter_parser.add_argument('--allow-delegation', action='store_true',
            help='Return user accounts that are not marked as \'sensitive and '\
                    'not allowed for delegation\'')
    invoke_userhunter_parser.add_argument('--check-access', action='store_true',
            help='Check if the current user has local admin access to the target servers')
    invoke_userhunter_parser.add_argument('--stealth', action='store_true',
            help='Only enumerate sessions from commonly used target servers')
    invoke_userhunter_parser.add_argument('--stealth-source', nargs='+', choices=['dfs', 'dc', 'file'],
            default=['dfs', 'dc', 'file'], help='The source of target servers to use, '\
                    '\'dfs\' (distributed file server), \'dc\' (domain controller), '\
                    'or \'file\' (file server) (default: all)')
    invoke_userhunter_parser.add_argument('--foreign-users', action='store_true',
            help='Only return users that are not part of the searched domain')
    invoke_userhunter_parser.add_argument('--stop-on-success', action='store_true',
            help='Stop hunting after finding target')
    invoke_userhunter_parser.add_argument('--show-all', action='store_true',
            help='Return all results')
    invoke_userhunter_parser.set_defaults(func=invoke_userhunter)

    # Parser for the invoke-processhunter command
    invoke_processhunter_parser = subparsers.add_parser('invoke-processhunter', help='Searches machines '\
            'for processes with specific name, or ran by specific users', parents=[ad_parser, hunter_parser])
    invoke_processhunter_parser.add_argument('--processname', dest='queried_processname',
            nargs='+', default=list(), help='Names of the process to hunt')
    invoke_processhunter_parser.add_argument('--stop-on-success', action='store_true',
            help='Stop hunting after finding target')
    invoke_processhunter_parser.add_argument('--show-all', action='store_true',
            help='Return all results')
    invoke_processhunter_parser.set_defaults(func=invoke_processhunter)

    # Parser for the invoke-eventhunter command
    invoke_eventhunter_parser = subparsers.add_parser('invoke-eventhunter', help='Searches machines '\
            'for events with specific name, or ran by specific users', parents=[ad_parser, hunter_parser])
    invoke_eventhunter_parser.add_argument('--search-days', dest='search_days',
            type=int, default=3, help='Number of days back to search logs for (default: %(default)s)')
    invoke_eventhunter_parser.set_defaults(func=invoke_eventhunter)

    args = parser.parse_args()
    if args.hashes:
        try:
            args.lmhash, args.nthash = args.hashes.split(':')
        except ValueError:
            args.lmhash, args.nthash = 'aad3b435b51404eeaad3b435b51404ee', args.hashes
        finally:
            args.password = str()
    else:
        args.lmhash = args.nthash = str()

    if args.password is None and not args.hashes:
        from getpass import getpass
        args.password = getpass('Password:')

    parsed_args = dict()
    for k, v in vars(args).items():
        if k not in ('func', 'hashes', 'submodule'):
            parsed_args[k] = v

    #try:
    results = args.func(**parsed_args)
    #except Exception, e:
        #print >>sys.stderr, repr(e)
        #sys.exit(-1)

    if results is not None:
        try:
            for x in results:
                    print(x)
        # for example, invoke_checklocaladminaccess returns a bool 
        except TypeError:
            print(results)

