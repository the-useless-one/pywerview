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

[![License](https://img.shields.io/github/license/the-useless-one/pywerview)](https://github.com/the-useless-one/pywerview/blob/master/LICENSE)
![Python versions](https://img.shields.io/pypi/pyversions/pywerview)
[![GitHub release](https://img.shields.io/github/v/release/the-useless-one/pywerview)](https://github.com/the-useless-one/pywerview/releases/latest)
[![PyPI version](https://img.shields.io/pypi/v/pywerview)](https://pypi.org/project/pywerview/)

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
* gssapi (Which requires `libkrb5-dev`)
* pycryptodomex (or pycryptodome)

## FUNCTIONALITIES

If you like living on the bleeding edge, check out the
[development branch](https://github.com/the-useless-one/pywerview/tree/develop).

Here's the list of available commands:

    $ pywerview.py --help
    usage: pywerview.py [-h]
                        {get-adobject,get-adserviceaccount,get-objectacl,get-netuser,get-netgroup,get-netcomputer,get-netdomaincontroller,get-netfileserver,get-dfsshare,get-netou,get-netsite,get-netsubnet,get-netdomaintrust,get-netgpo,get-netpso,get-domainpolicy,get-gpttmpl,get-netgpogroup,find-gpocomputeradmin,find-gpolocation,get-netgroupmember,get-netsession,get-localdisks,get-netdomain,get-netshare,get-netloggedon,get-netlocalgroup,invoke-checklocaladminaccess,get-netprocess,get-userevent,invoke-userhunter,invoke-processhunter,invoke-eventhunter}
                        ...

    Rewriting of some PowerView's functionalities in Python

    optional arguments:
      -h, --help            show this help message and exit

    Subcommands:
      Available subcommands

      {get-adobject,get-adserviceaccount,get-objectacl,get-netuser,get-netgroup,get-netcomputer,get-netdomaincontroller,get-netfileserver,get-dfsshare,get-netou,get-netsite,get-netsubnet,get-netdomaintrust,get-netgpo,get-netpso,get-domainpolicy,get-gpttmpl,get-netgpogroup,find-gpocomputeradmin,find-gpolocation,get-netgroupmember,get-netsession,get-localdisks,get-netdomain,get-netshare,get-netloggedon,get-netlocalgroup,invoke-checklocaladminaccess,get-netprocess,get-userevent,invoke-userhunter,invoke-processhunter,invoke-eventhunter}
        get-adobject        Takes a domain SID, samAccountName or name, and return the associated object
        get-adserviceaccount
                            Returns a list of all the gMSA of the specified domain (you need privileged account to retrieve passwords)
        get-objectacl       Takes a domain SID, samAccountName or name, and return the ACL of the associated object
        get-netuser         Queries information about a domain user
        get-netgroup        Get a list of all current domain groups, or a list of groups a domain user is member of
        get-netcomputer     Queries informations about domain computers
        get-netdomaincontroller
                            Get a list of domain controllers for the given domain
        get-netfileserver   Return a list of file servers, extracted from the domain users' homeDirectory, scriptPath, and profilePath fields
        get-dfsshare        Return a list of all fault tolerant distributed file systems for a given domain
        get-netou           Get a list of all current OUs in the domain
        get-netsite         Get a list of all current sites in the domain
        get-netsubnet       Get a list of all current subnets in the domain
        get-netdomaintrust  Returns a list of all the trusts of the specified domain
        get-netgpo          Get a list of all current GPOs in the domain
        get-netpso          Get a list of all current PSOs in the domain
        get-domainpolicy    Returns the default domain or DC policy for the queried domain or DC
        get-gpttmpl         Helper to parse a GptTmpl.inf policy file path into a custom object
        get-netgpogroup     Parses all GPOs in the domain that set "Restricted Group" or "Groups.xml"
        find-gpocomputeradmin
                            Takes a computer (or OU) and determine who has administrative access to it via GPO
        find-gpolocation    Takes a username or a group name and determine the computers it has administrative access to via GPO
        get-netgroupmember  Return a list of members of a domain group
        get-netsession      Queries a host to return a list of active sessions on the host (you can use local credentials instead of domain credentials)
        get-localdisks      Queries a host to return a list of active disks on the host (you can use local credentials instead of domain credentials)
        get-netdomain       Queries a host for available domains
        get-netshare        Queries a host to return a list of available shares on the host (you can use local credentials instead of domain credentials)
        get-netloggedon     This function will execute the NetWkstaUserEnum RPC call to query a given host for actively logged on users
        get-netlocalgroup   Gets a list of members of a local group on a machine, or returns every local group. You can use local credentials instead of domain credentials, however, domain credentials are needed
                            to resolve domain SIDs.
        invoke-checklocaladminaccess
                            Checks if the given user has local admin access on the given host
        get-netprocess      This function will execute the 'Select * from Win32_Process' WMI query to a given host for a list of executed process
        get-userevent       This function will execute the 'SELECT * from Win32_NTLogEvent' WMI query to a given host for a list of executed process
        invoke-userhunter   Finds which machines domain users are logged into
        invoke-processhunter
                            Searches machines for processes with specific name, or ran by specific users
        invoke-eventhunter  Searches machines for events with specific name, or ran by specific users

Take a look at the [wiki](https://github.com/the-useless-one/pywerview/wiki) to
see a more detailed usage of every command.

*Attention:* in every command, the used domain name must be the post-Win2k UPN,
and not the Win2k compatible name.

For example, my domain name is `uselessdomain.local`. The Win2K compatible name
is `USELESSDOMAIN`. In every command,  I must use __`uselessdomain.local`__ as
an argument, and __not__ `USELESSDOMAIN`.

## GLOBAL ARGUMENTS

### LOGGING

You can provide a logging level to `pywerview` modules by using `-l` or `--logging-level` options. Supported levels are:

* `CRITICAL`: Only critical errors are displayed **(default)**
* `WARNING` Warnings are displayed, along with citical errors
* `DEBUG`: Debug level (caution: **very** verbose)
* `ULTRA`: Extreme debugging level (caution: **very very** verbose)

(level names are case insensitive)

### Kerberos authentication

Kerberos authentication is now (partially) supported, which means you can
pass the ticket and other stuff. To authenticate via Kerberos:

1. Point the `KRB5CCNAME` environment variable to your cache credential file.
2. Use the `-k` option in your function call, or the `do_kerberos` in your
   library call.

```console
$ klist stormtroopers.ccache
Ticket cache: FILE:stormtroopers.ccache
Default principal: stormtroopers@CONTOSO.COM

Valid starting       Expires              Service principal
10/03/2022 16:46:45  11/03/2022 02:46:45  ldap/srv-ad.contoso.com@CONTOSO.COM
	renew until 11/03/2022 16:43:17
$ KRB5CCNAME=stormtroopers.ccache python3 pywerview.py get-netcomputer -t srv-ad.contoso.com -u stormtroopers -k 
dnshostname: centos.contoso.com 

dnshostname: debian.contoso.com 

dnshostname: Windows7.contoso.com 

dnshostname: Windows10.contoso.com 

dnshostname: SRV-MAIL.contoso.com 

dnshostname: SRV-AD.contoso.com 
```

If your cache credential file contains a corresponding TGS, or a TGT for your
calling user, Kerberos authentication will be used.

__SPN patching is partial__. Right now, we're in a mixed configuration where we
use `ldap3` for LDAP commands and `impacket` for the other protocols (SMB,
RPC). That is because `impacket`'s LDAP implementation has several problems,
such as mismanagement of non-ASCII characters (which is problematic for us
baguette-eaters).

`ldap3` uses `gssapi` to authenticate with Kerberos, and `gssapi` needs the
full hostname in the SPN of a ticket, otherwise it throws an error. It would
be possible to patch an SPN with an incomplete hostname, however it's not done
for now.

For any functions that only rely on `impacket` (SMB or RPC functions), you can
use tickets with SPNs with an incomplete hostname. In the following example, we
use an LDAP ticket with an incomplete hostname for an SMB function, without any
trouble. You just have to make sure that the `--computername` argument matches
this incomplete hostname in the SPN:

```console
$ klist skywalker.ccache
Ticket cache: FILE:skywalker.ccache
Default principal: skywalker@CONTOSO.COM

Valid starting       Expires              Service principal
13/04/2022 14:26:59  14/04/2022 00:26:58  ldap/srv-ad@CONTOSO.COM
	renew until 14/04/2022 14:23:29
$ KRB5CCNAME=skywalker.ccache python3 pywerview.py get-localdisks --computername srv-ad -u skywalker -k  
disk: A: 

disk: C: 

disk: D:
```

To recap:

|           SPN in the ticket           | Can be used with LDAP functions | Can be used with SMB/RPC functions |
| :-----------------------------------: | :-----------------------------: | :--------------------------------: |
| `ldap/srv-ad.contoso.com@CONTOSO.COM` |              ✔️                  |                 ✔️                  |
| `cifs/srv-ad.contoso.com@CONTOSO.COm` |              ✔️                  |                 ✔️                  |
|       `ldap/srv-ad@CONTOSO.COM`       |              ❌                 |                 ✔️                  |

### TLS CONNECTION

You can force a connection to the LDAPS port by using the `--tls` switch. It
can be necessary with some functions, for example when retrieving gMSA
passwords with `get-adserviceaccount`:

```console
$ python3 pywerview.py get-adserviceaccount -t srv-ad.contoso.com -u 'SRV-MAIL$' --hashes $NT_HASH --resolve-sids
distinguishedname:       CN=gMSA-01,CN=Managed Service Accounts,DC=contoso,DC=com
objectsid:               S-1-5-21-863927164-4106933278-53377030-3115
samaccountname:          gMSA-01$
msds-groupmsamembership: CN=SRV-MAIL,CN=Computers,DC=contoso,DC=com
description:
enabled:                 True
$ python3 pywerview.py get-adserviceaccount -t srv-ad.contoso.com -u 'SRV-MAIL$' --hashes $NT_HASH --resolve-sids --tls
distinguishedname:       CN=gMSA-01,CN=Managed Service Accounts,DC=contoso,DC=com
objectsid:               S-1-5-21-863927164-4106933278-53377030-3115
samaccountname:          gMSA-01$
msds-managedpassword:    69730ce3914ac6[redacted]
msds-groupmsamembership: CN=SRV-MAIL,CN=Computers,DC=contoso,DC=com
description:
enabled:                 True
```

### JSON OUTPUT

Pywerview can print results in json format by using the `--json` switch.

## TODO

* Many, many more PowerView functionalities to implement. I'll now focus on
  forest functions, then inter-forest trust functions
* Lots of rewrite due to the last version of PowerView
* Gracefully fail against Unix machines running Samba
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

Yannick Méheut [yannick (at) meheut (dot) org] - Copyright © 2022

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
[https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).

