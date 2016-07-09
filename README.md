# PywerView
      ____                        __     ___
     |  _ \ _   ___      _____ _ _\ \   / (_) _____      __
     | |_) | | | \ \ /\ / / _ \ '__\ \ / /| |/ _ \ \ /\ / /
     |  __/| |_| |\ V  V /  __/ |   \ V / | |  __/\ V  V /
     |_|    \__, | \_/\_/ \___|_|    \_/  |_|\___| \_/\_/
            |___/

A (partial) Python rewriting of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s
[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon).

Fork me on [GitHub](https://github.com/the-useless-one/pywerview).

## HISTORY

As a pentester, I love using PowerView during my assignments. It makes it so
easy to find vulnerable machines, or list what domain users were added to the
local Administrators group of a machine, and much more.

However, running PowerView on a computer which is not connected to the domain
is a pain: I always find myself using [mimikatz](https://github.com/gentilkiwi/mimikatz/)'s
`sekurlsa::pth` to run a Powershell prompt with stolen domain credentials, and
that's not easy to script. Plus, I'm a Linux guy and I've always found it a
shame that there were no complete Windows/Active Directory enumeration tool on
Linux.

That's why I decided to rewrite some of PowerView's functionalities in Python,
using the wonderful [impacket](https://github.com/CoreSecurity/impacket/)
library.

## DISCLAIMER

This tool is far from complete (as you'll see in the [TODO](#todo) section)! I
still have a lot more awesome PowerView functionalities to implement (the user
hunting functions, the GPO functions, the local process enumeration, etc.),
but I still think it can be useful as is.

It's also (very) possible that there are (many) bugs in the code: I've only
tested the simplest test cases. If you use this tool during an assignment and
you get an error, please, open an issue with the error and the conditions that
triggered this error.

Also, blah blah blah, don't use it for evil purposes.

## REQUIREMENTS

* Python 2.7
* impacket 0.9.15

## USAGE

*Attention:* in every command, the used domain name must be the post-Win2k UPN,
and not the Win2k compatible name.

For example, my domain name is `uselessdomain.local`. The Win2K compatible name
is `USELESSDOMAIN`. In every command,  I must use __`uselessdomain.local`__ as
an argument, and __not__ `USELESSDOMAIN`.

    $ python pywerview.py -h
    usage: pywerview.py [-h]
                        {get-adobject,get-netuser,get-netgroup,get-netcomputer,get-netdomaincontroller,get-netfileserver,get-netou,get-netsite,get-netsubnet,get-netgpo,get-netgroupmember,get-netsession,get-netshare,get-netloggedon,get-netlocalgroup,invoke-checklocaladminaccess}
                        ...

    Rewriting of some PowerView's functionalities in Python

    optional arguments:
      -h, --help            show this help message and exit

    Subcommands:
      Available subcommands

      {get-adobject,get-netuser,get-netgroup,get-netcomputer,get-netdomaincontroller,get-netfileserver,get-netou,get-netsite,get-netsubnet,get-netgpo,get-netgroupmember,get-netsession,get-netshare,get-netloggedon,get-netlocalgroup,invoke-checklocaladminaccess}
        get-adobject        Takes a domain SID, samAccountName or name, and return
                            the associated object
        get-netuser         Queries information about a domain user
        get-netgroup        Get a list of all current domain groups, or a list of
                            groups a domain user is member of
        get-netcomputer     Queries informations about domain computers
        get-netdomaincontroller
                            Get a list of domain controllers for the given domain
        get-netfileserver   Return a list of file servers, extracted from the
                            domain users' homeDirectory, scriptPath, and
                            profilePath fields
        get-netou           Get a list of all current OUs in the domain
        get-netsite         Get a list of all current sites in the domain
        get-netsubnet       Get a list of all current subnets in the domain
        get-netgpo          Get a list of all current GPOs in the domain
        get-netgroupmember  Return a list of members of a domain groups
        get-netsession      Queries a host to return a list of active sessions on
                            the host (you can use local credentials instead of
                            domain credentials)
        get-netshare        Queries a host to return a list of available shares on
                            the host (you can use local credentials instead of
                            domain credentials)
        get-netloggedon     This function will execute the NetWkstaUserEnum RPC
                            call ti query a given host for actively logged on
                            users
        get-netlocalgroup   Gets a list of members of a local group on a machine,
                            or returns every local group. You can use local
                            credentials instead of domain credentials, however,
                            domain credentials are needed to resolve domain SIDs.
        invoke-checklocaladminaccess
                            Checks if the given user has local admin acces on the
                            given host

### get-adobject
    usage: pywerview.py get-adobject [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                     [--hashes LMHASH:NTHASH] -t DOMAIN_CONTROLLER
                                     [--sid QUERIED_SID]
                                     [--sam-account-name QUERIED_SAM_ACCOUNT_NAME]
                                     [--name QUERIED_NAME] [-d QUERIED_DOMAIN]
                                     [-a ADS_PATH]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --sid QUERIED_SID     SID to query (wildcards accepted)
      --sam-account-name QUERIED_SAM_ACCOUNT_NAME
                            samAccountName to query (wildcards accepted)
      --name QUERIED_NAME   Name to query (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path

### get-netcomputer
    usage: pywerview.py get-netcomputer [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                        [--hashes LMHASH:NTHASH] -t
                                        DOMAIN_CONTROLLER
                                        [--computername QUERIED_COMPUTERNAME]
                                        [-os QUERIED_OS] [-sp QUERIED_SP]
                                        [-spn QUERIED_SPN] [-d QUERIED_DOMAIN]
                                        [-a ADS_PATH] [--printers]
                                        [--unconstrained] [--ping] [--full-data]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --computername QUERIED_COMPUTERNAME
                            Computer name to query
      -os QUERIED_OS, --operating-system QUERIED_OS
                            Return computers with a specific operating system
                            (wildcards accepted)
      -sp QUERIED_SP, --service-pack QUERIED_SP
                            Return computers with a specific service pack
                            (wildcards accepted)
      -spn QUERIED_SPN, --service-principal-name QUERIED_SPN
                            Return computers with a specific service principal
                            name (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      --printers            Query only printers
      --unconstrained       Query only computers with unconstrained delegation
      --ping                Ping computers (will only return up computers)
      --full-data           If set, returns full information on the groups,
                            otherwise, just the dnsHostName

### get-netdomaincontroller
    usage: pywerview.py get-netdomaincontroller [-h] [-w DOMAIN] -u USER
                                                [-p PASSWORD]
                                                [--hashes LMHASH:NTHASH] -t
                                                DOMAIN_CONTROLLER
                                                [-d QUERIED_DOMAIN]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query

### get-netfileserver
    usage: pywerview.py get-netfileserver [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                          [--hashes LMHASH:NTHASH] -t
                                          DOMAIN_CONTROLLER
                                          [--target-users TARGET_USER [TARGET_USER ...]]
                                          [-d QUERIED_DOMAIN]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --target-users TARGET_USER [TARGET_USER ...]
                            A list of users to target to find file servers
                            (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query

### get-netgpo
    usage: pywerview.py get-netgpo [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                   [--hashes LMHASH:NTHASH] -t DOMAIN_CONTROLLER
                                   [--gponame QUERIED_GPONAME]
                                   [--displayname QUERIED_DISPLAYNAME]
                                   [-d QUERIED_DOMAIN] [-a ADS_PATH]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --gponame QUERIED_GPONAME
                            GPO name to query for (wildcards accepted)
      --displayname QUERIED_DISPLAYNAME
                            Display name to query for (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path

### get-netgroup
    usage: pywerview.py get-netgroup [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                     [--hashes LMHASH:NTHASH] -t DOMAIN_CONTROLLER
                                     [--groupname QUERIED_GROUPNAME]
                                     [--sid QUERIED_SID]
                                     [--username QUERIED_USERNAME]
                                     [-d QUERIED_DOMAIN] [-a ADS_PATH]
                                     [--full-data] [--admin-count]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --groupname QUERIED_GROUPNAME
                            Group to query (wildcards accepted)
      --sid QUERIED_SID     Group SID to query
      --username QUERIED_USERNAME
                            Username to query: will list the groups this user is a
                            member of (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      --full-data           If set, returns full information on the groups,
                            otherwise, just the samAccountName
      --admin-count         Query only users with adminCount=1

### get-netgroupmember
    usage: pywerview.py get-netgroupmember [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                           [--hashes LMHASH:NTHASH] -t
                                           DOMAIN_CONTROLLER
                                           [--groupname QUERIED_GROUPNAME]
                                           [--sid QUERIED_SID] [-d QUERIED_DOMAIN]
                                           [-a ADS_PATH] [-r]
                                           [--use-matching-rule] [--full-data]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --groupname QUERIED_GROUPNAME
                            Group to query, defaults to the 'Domain Admins' group
                            (wildcards accepted)
      --sid QUERIED_SID     SID to query
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      -r, --recurse         If the group member is a group, try to resolve its
                            members as well
      --use-matching-rule   Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search
                            query when -Recurse is specified. Much faster than
                            manual recursion, but doesn't reveal cross-domain
                            groups
      --full-data           If set, returns full information on the members

### get-netlocalgroup
    usage: pywerview.py get-netlocalgroup [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                          [--hashes LMHASH:NTHASH]
                                          [--computername TARGET_COMPUTERNAME]
                                          [--groupname QUERIED_GROUPNAME]
                                          [--list-groups] [-t DOMAIN_CONTROLLER]
                                          [-r]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      --computername TARGET_COMPUTERNAME
                            Computer to list the local groups on
      --groupname QUERIED_GROUPNAME
                            Group to list the members of (defaults to the local
                            'Administrators' group
      --list-groups         If set, returns a list of the local groups on the
                            targets
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller (used to resolve
                            domain SIDs)
      -r, --recurse         If the group member is a domain group, try to resolve
                            its members as well

### get-netloggedon
    usage: pywerview.py get-netloggedon [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                        [--hashes LMHASH:NTHASH]
                                        [--computername TARGET_COMPUTERNAME]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      --computername TARGET_COMPUTERNAME
                            Computer to list logged on users on

### get-netou
    usage: pywerview.py get-netou [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                  [--hashes LMHASH:NTHASH] -t DOMAIN_CONTROLLER
                                  [--ouname QUERIED_OUNAME] [--guid QUERIED_GUID]
                                  [-d QUERIED_DOMAIN] [-a ADS_PATH] [--full-data]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --ouname QUERIED_OUNAME
                            OU name to query (wildcards accepted)
      --guid QUERIED_GUID   Only return OUs with the specified GUID in their
                            gplink property.
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      --full-data           If set, returns full information on the OUs,
                            otherwise, just the adspath

### get-netsession
    usage: pywerview.py get-netsession [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                       [--hashes LMHASH:NTHASH]
                                       [--computername TARGET_COMPUTERNAME]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      --computername TARGET_COMPUTERNAME
                            Computer to list sessions on

### get-netshare
    usage: pywerview.py get-netshare [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                     [--hashes LMHASH:NTHASH]
                                     [--computername TARGET_COMPUTERNAME]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      --computername TARGET_COMPUTERNAME
                            Computer to list shares on

### get-netsite
    usage: pywerview.py get-netsite [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                    [--hashes LMHASH:NTHASH] -t DOMAIN_CONTROLLER
                                    [--sitename QUERIED_SITENAME]
                                    [--guid QUERIED_GUID] [-d QUERIED_DOMAIN]
                                    [-a ADS_PATH] [--full-data]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --sitename QUERIED_SITENAME
                            Site name to query (wildcards accepted)
      --guid QUERIED_GUID   Only return sites with the specified GUID in their
                            gplink property.
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      --full-data           If set, returns full information on the sites,
                            otherwise, just the name

### get-netsubnet
    usage: pywerview.py get-netsubnet [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                      [--hashes LMHASH:NTHASH] -t
                                      DOMAIN_CONTROLLER
                                      [--sitename QUERIED_SITENAME]
                                      [-d QUERIED_DOMAIN] [-a ADS_PATH]
                                      [--full-data]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --sitename QUERIED_SITENAME
                            Only return subnets for the specified site name
                            (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      --full-data           If set, returns full information on the subnets,
                            otherwise, just the name

### get-netuser
    usage: pywerview.py get-netuser [-h] [-w DOMAIN] -u USER [-p PASSWORD]
                                    [--hashes LMHASH:NTHASH] -t DOMAIN_CONTROLLER
                                    [--username QUERIED_USERNAME]
                                    [-d QUERIED_DOMAIN] [-a ADS_PATH]
                                    [--unconstrained] [--admin-count]
                                    [--allow-delegation] [--spn]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                            IP address of the Domain Controller to target
      --username QUERIED_USERNAME
                            Username to query (wildcards accepted)
      -d QUERIED_DOMAIN, --domain QUERIED_DOMAIN
                            Domain to query
      -a ADS_PATH, --ads-path ADS_PATH
                            Additional ADS path
      --unconstrained       Query only users with unconstrained delegation
      --admin-count         Query only users with adminCount=1
      --allow-delegation    Return user accounts that are not marked as 'sensitive
                            and not allowed for delegation'
      --spn                 Query only users with not-null Service Principal Names

### invoke-checklocaladminaccess
    usage: pywerview.py invoke-checklocaladminaccess [-h] [-w DOMAIN] -u USER
                                                     [-p PASSWORD]
                                                     [--hashes LMHASH:NTHASH]
                                                     [--computername TARGET_COMPUTERNAME]

    optional arguments:
      -h, --help            show this help message and exit
      -w DOMAIN, --workgroup DOMAIN
                            Name of the domain we authenticate with
      -u USER, --user USER  Username used to connect to the Domain Controller
      -p PASSWORD, --password PASSWORD
                            Password associated to the username
      --hashes LMHASH:NTHASH
                            NTLM hashes, format is LMHASH:NTHASH
      --computername TARGET_COMPUTERNAME
                            Computer to test local admin access on

## TODO

* Many, many, many more PowerView functionalities to implement (I'll probably
  focus on the user hunting functions)!
* Support Kerberos authentication
* Perform range cycling in `get-netgroupmember`
* Manage ADS path starting with `GC://`
* Try to fall back to `tcp/139` for RPC communications if `tcp/445` is closed
* Comment and document the code

## THANKS

Thanks to the PowerSploit team for an awesome tool. Thanks to CoreSecurity for
this complete and comprehensive library that is impacket. Special thanks to
@asolino for his help.

## COPYRIGHT

PywerView - A Python rewriting of PowerSploit's PowerView

Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2016

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see
[http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
