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
* impacket >= 0.9.16-dev

## USAGE

*Attention:* in every command, the used domain name must be the post-Win2k UPN,
and not the Win2k compatible name.

For example, my domain name is `uselessdomain.local`. The Win2K compatible name
is `USELESSDOMAIN`. In every command,  I must use __`uselessdomain.local`__ as
an argument, and __not__ `USELESSDOMAIN`.

Take a look at the [wiki](https://github.com/the-useless-one/pywerview/wiki) to
see the list of available commands.

## TODO

* Many, many, many more PowerView functionalities to implement. I'll focus on
  the (process) hunting functions and the GPO functions.
* Support Kerberos authentication
* Perform range cycling in `get-netgroupmember`
* Manage ADS path starting with `GC://`
* Try to fall back to `tcp/139` for RPC communications if `tcp/445` is closed
* Comment and document the code

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
