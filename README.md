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

![License](https://img.shields.io/github/license/the-useless-one/pywerview.svg?maxAge=2592000)
![Python versions](https://img.shields.io/pypi/pyversions/pywerview.svg?maxAge=2592000)
[![GitHub release](https://img.shields.io/github/release/the-useless-one/pywerview.svg?maxAge=2592001&label=GitHub%20release)](https://github.com/the-useless-one/pywerview/releases/latest)
[![PyPI version](https://img.shields.io/pypi/v/pywerview.svg?maxAge=2592000)](https://pypi.python.org/pypi/pywerview)

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
using the wonderful [impacket](https://github.com/SecureAuthCorp/impacket)
library.

*Update:* I haven't tested the last version of PowerView yet, which can run
from a machine not connected to a domain. I don't know if it works correctly
under Linux using Powershell. If anyone has had any experience with this at all,
you can contact me, I'm really interested. We'll see if pywerview has become
obsoleted ;) but I think I'll continue working on it eitherway: I'd still
rather use Python than Powershell on Linux, and I'm learning a lot! Plus, it
may integrated in existing Linux tools written in Python. It's still great news
that PowerView now supports machines not connected to the domain!

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

* Python 3.6
* impacket >= 0.9.22
* ldap3 >= 2.8.1

## FUNCTIONALITIES

If you like living on the bleeding edge, check out the
[development branch](https://github.com/the-useless-one/pywerview/tree/develop).

Here's the list of available commands:

    $ ./pywerview.py --help
    usage: pywerview.py [-h]
                        {get-adobject,get-netuser,get-netgroup,get-netcomputer,get-netdomaincontroller,get-netfileserver,get-dfsshare,get-netou,get-netsite,get-netsubnet,get-netgpo,get-domainpolicy,get-gpttmpl,get-netgpogroup,get-netgroupmember,get-netsession,get-localdisks,get-netdomain,get-netshare,get-netloggedon,get-netlocalgroup,invoke-checklocaladminaccess,get-netprocess,get-userevent,invoke-userhunter,invoke-processhunter,invoke-eventhunter}
                        ...

    Rewriting of some PowerView's functionalities in Python

    optional arguments:
      -h, --help            show this help message and exit

    Subcommands:
      Available subcommands

      {get-adobject,get-netuser,get-netgroup,get-netcomputer,get-netdomaincontroller,get-netfileserver,get-dfsshare,get-netou,get-netsite,get-netsubnet,get-netgpo,get-domainpolicy,get-gpttmpl,get-netgpogroup,find-gpocomputeradmin,find-gpolocation,get-netgroupmember,get-netsession,get-localdisks,get-netdomain,get-netshare,get-netloggedon,get-netlocalgroup,invoke-checklocaladminaccess,get-netprocess,get-userevent,invoke-userhunter,invoke-processhunter,invoke-eventhunter}
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
        get-dfsshare        Return a list of all fault tolerant distributed file
                            systems for a given domain
        get-netou           Get a list of all current OUs in the domain
        get-netsite         Get a list of all current sites in the domain
        get-netsubnet       Get a list of all current subnets in the domain
        get-netgpo          Get a list of all current GPOs in the domain
        get-domainpolicy    Returns the default domain or DC policy for the
                            queried domain or DC
        get-gpttmpl         Helper to parse a GptTmpl.inf policy file path into a
                            custom object
        get-netgpogroup     Parses all GPOs in the domain that set "Restricted
                            Group" or "Groups.xml"
        find-gpocomputeradmin
                            Takes a computer (or OU) and determine who has
                            administrative access to it via GPO
        find-gpolocation    Takes a username or a group name and determine the
                            computers it has administrative access to via GPO
        get-netgroupmember  Return a list of members of a domain group
        get-netsession      Queries a host to return a list of active sessions on
                            the host (you can use local credentials instead of
                            domain credentials)
        get-localdisks      Queries a host to return a list of active disks on the
                            host (you can use local credentials instead of domain
                            credentials)
        get-netdomain       Queries a host for available domains
        get-netshare        Queries a host to return a list of available shares on
                            the host (you can use local credentials instead of
                            domain credentials)
        get-netloggedon     This function will execute the NetWkstaUserEnum RPC
                            call to query a given host for actively logged on
                            users
        get-netlocalgroup   Gets a list of members of a local group on a machine,
                            or returns every local group. You can use local
                            credentials instead of domain credentials, however,
                            domain credentials are needed to resolve domain SIDs.
        invoke-checklocaladminaccess
                            Checks if the given user has local admin access on the
                            given host
        get-netprocess      This function will execute the 'Select * from
                            Win32_Process' WMI query to a given host for a list of
                            executed process
        get-userevent       This function will execute the 'Select * from
                            Win32_Process' WMI query to a given host for a list of
                            executed process
        invoke-userhunter   Finds which machines domain users are logged into
        invoke-processhunter
                            Searches machines for processes with specific name, or
                            ran by specific users
        invoke-eventhunter  Searches machines for events with specific name, or
                            ran by specific users

Take a look at the [wiki](https://github.com/the-useless-one/pywerview/wiki) to
see a more detailed usage of every command.

*Attention:* in every command, the used domain name must be the post-Win2k UPN,
and not the Win2k compatible name.

For example, my domain name is `uselessdomain.local`. The Win2K compatible name
is `USELESSDOMAIN`. In every command,  I must use __`uselessdomain.local`__ as
an argument, and __not__ `USELESSDOMAIN`.

## TODO

* Many, many more PowerView functionalities to implement. I'll now focus on
  forest functions, then inter-forest trust functions
* Lots of rewrite due to the last version of PowerView
* Implement a debugging mode (for easier troubleshooting)
* Gracefully fail against Unix machines running Samba
* Support Kerberos authentication
* Perform range cycling in `get-netgroupmember`
* Manage request to the Global Catalog
* Try to fall back to `tcp/139` for RPC communications if `tcp/445` is closed
* Comment, document, and clean the code

## THANKS

* Thanks to the [@PowerSploit](https://github.com/PowerShellMafia/PowerSploit/)
  team for an awesome tool.
* Thanks to [@CoreSecurity](https://github.com/CoreSecurity/) for this complete
  and comprehensive library that is [impacket](https://github.com/CoreSecurity/impacket).
* Special thanks to [@asolino](https://github.com/asolino) for his help on
  developing using impacket.
* Thanks to [@byt3bl33d3r](https://github.com/byt3bl33d3r) for his
  contributions.
* Thanks to [@ThePirateWhoSmellsOfSunflowers](https://github.com/ThePirateWhoSmellsOfSunflowers)
  for his debugging, love you baby :heart:
* Thanks to [@mpgn](https://github.com/mpgn) for his python 3 contributions.

## COPYRIGHT

PywerView - A Python rewriting of PowerSploit's PowerView

Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2021

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

