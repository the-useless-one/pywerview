#!/usr/bin/env python
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

from pywerview.functions.net import NetRequester
from pywerview.functions.gpo import GPORequester
from pywerview.functions.misc import Misc
from pywerview.functions.hunting import UserHunter, ProcessHunter, EventHunter

def get_adobject(domain_controller, domain, user, password=str(),
                lmhash=str(), nthash=str(), queried_domain=str(), queried_sid=str(),
                queried_name=str(), queried_sam_account_name=str(), ads_path=str(),
                custom_filter=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_adobject(queried_domain=queried_domain,
                    queried_sid=queried_sid, queried_name=queried_name,
                    queried_sam_account_name=queried_sam_account_name,
                    ads_path=ads_path, custom_filter=custom_filter)

def get_netuser(domain_controller, domain, user, password=str(), lmhash=str(),
                nthash=str(), queried_username=str(), queried_domain=str(), ads_path=str(),
                admin_count=False, spn=False, unconstrained=False, allow_delegation=False,
                preauth_notreq=False, custom_filter=str(),
                attributes=[]):
    requester = NetRequester(domain_controller, domain, user, password,
                             lmhash, nthash)
    return requester.get_netuser(queried_username=queried_username,
                                    queried_domain=queried_domain, ads_path=ads_path, admin_count=admin_count,
                                    spn=spn, unconstrained=unconstrained, allow_delegation=allow_delegation,
                                    preauth_notreq=preauth_notreq, custom_filter=custom_filter,
                                    attributes=attributes)

def get_netgroup(domain_controller, domain, user, password=str(),
                lmhash=str(), nthash=str(), queried_groupname='*', queried_sid=str(),
                queried_username=str(), queried_domain=str(), ads_path=str(),
                admin_count=False, full_data=False, custom_filter=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                lmhash, nthash)
    return requester.get_netgroup(queried_groupname=queried_groupname,
                                    queried_sid=queried_sid, queried_username=queried_username,
                                    queried_domain=queried_domain, ads_path=ads_path, admin_count=admin_count,
                                    full_data=full_data, custom_filter=custom_filter)

def get_netcomputer(domain_controller, domain, user, password=str(),
                    lmhash=str(), nthash=str(), queried_computername='*', queried_spn=str(),
                    queried_os=str(), queried_sp=str(), queried_domain=str(), ads_path=str(),
                    printers=False, unconstrained=False, ping=False, full_data=False,
                    custom_filter=str(), attributes=[]):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netcomputer(queried_computername=queried_computername,
                                        queried_spn=queried_spn, queried_os=queried_os, queried_sp=queried_sp,
                                        queried_domain=queried_domain, ads_path=ads_path, printers=printers,
                                        unconstrained=unconstrained, ping=ping, full_data=full_data,
                                        custom_filter=custom_filter, attributes=attributes)

def get_netdomaincontroller(domain_controller, domain, user, password=str(),
                                 lmhash=str(), nthash=str(), queried_domain=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netdomaincontroller(queried_domain=queried_domain)

def get_netfileserver(domain_controller, domain, user, password=str(),
                                 lmhash=str(), nthash=str(), queried_domain=str(), target_users=list()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netfileserver(queried_domain=queried_domain,
                                            target_users=target_users)

def get_dfsshare(domain_controller, domain, user, password=str(),
                 lmhash=str(), nthash=str(), version=['v1', 'v2'], queried_domain=str(),
                 ads_path=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_dfsshare(version=version, queried_domain=queried_domain, ads_path=ads_path)

def get_netou(domain_controller, domain, user, password=str(), lmhash=str(),
              nthash=str(), queried_domain=str(), queried_ouname='*', queried_guid=str(),
              ads_path=str(), full_data=False):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netou(queried_domain=queried_domain,
                                   queried_ouname=queried_ouname, queried_guid=queried_guid, ads_path=ads_path,
                                   full_data=full_data)

def get_netsite(domain_controller, domain, user, password=str(), lmhash=str(),
                nthash=str(), queried_domain=str(), queried_sitename=str(),
                queried_guid=str(), ads_path=str(), ads_prefix='CN=Sites,CN=Configuration',
                full_data=False):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netsite(queried_domain=queried_domain,
                                    queried_sitename=queried_sitename, queried_guid=queried_guid,
                                    ads_path=ads_path, ads_prefix=ads_prefix, full_data=full_data)

def get_netsubnet(domain_controller, domain, user, password=str(),
                  lmhash=str(), nthash=str(), queried_domain=str(), queried_sitename=str(),
                  ads_path=str(), ads_prefix='CN=Sites,CN=Configuration', full_data=False):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netsubnet(queried_domain=queried_domain,
                                       queried_sitename=queried_sitename, ads_path=ads_path, ads_prefix=ads_prefix,
                                       full_data=full_data)

def get_netdomaintrust(domain_controller, domain, user, password=str(),
                  lmhash=str(), nthash=str(), queried_domain=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netdomaintrust(queried_domain=queried_domain)

def get_netgroupmember(domain_controller, domain, user, password=str(),
                       lmhash=str(), nthash=str(), queried_groupname=str(), queried_sid=str(),
                       queried_domain=str(), ads_path=str(), recurse=False, use_matching_rule=False,
                       full_data=False, custom_filter=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netgroupmember(queried_groupname=queried_groupname,
                                            queried_sid=queried_sid, queried_domain=queried_domain,
                                            ads_path=ads_path, recurse=recurse,
                                            use_matching_rule=use_matching_rule,
                                            full_data=full_data, custom_filter=custom_filter)

def get_netsession(target_computername, domain, user, password=str(),
                   lmhash=str(), nthash=str()):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netsession()

def get_netshare(target_computername, domain, user, password=str(),
                                 lmhash=str(), nthash=str()):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netshare()

def get_localdisks(target_computername, domain, user, password=str(),
                                 lmhash=str(), nthash=str()):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash)
    return requester.get_localdisks()

def get_netdomain(domain_controller, domain, user, password=str(),
                                 lmhash=str(), nthash=str()):
    requester = NetRequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netdomain()

def get_netloggedon(target_computername, domain, user, password=str(),
                                 lmhash=str(), nthash=str()):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netloggedon()

def get_netlocalgroup(target_computername, domain_controller, domain, user,
                      password=str(), lmhash=str(), nthash=str(), queried_groupname=str(),
                      list_groups=False, recurse=False):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash, domain_controller)
    return requester.get_netlocalgroup(queried_groupname=queried_groupname,
                                           list_groups=list_groups, recurse=recurse)

def get_netprocess(target_computername, domain, user, password=str(),
                   lmhash=str(), nthash=str()):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netprocess()

def get_userevent(target_computername, domain, user, password=str(),
                   lmhash=str(), nthash=str(), event_type=['logon', 'tgt'],
                   date_start=5):
    requester = NetRequester(target_computername, domain, user, password,
                                 lmhash, nthash)
    return requester.get_userevent(event_type=event_type,
                                       date_start=date_start)

def get_netgpo(domain_controller, domain, user, password=str(),
               lmhash=str(), nthash=str(), queried_gponame='*',
               queried_displayname=str(), queried_domain=str(), ads_path=str()):
    requester = GPORequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.get_netgpo(queried_gponame=queried_gponame,
                                    queried_displayname=queried_displayname,
                                    queried_domain=queried_domain, ads_path=ads_path)

def get_domainpolicy(domain_controller, domain, user, password=str(),
                     lmhash=str(), nthash=str(), source='domain', queried_domain=str(),
                     resolve_sids=False):
    requester = GPORequester(domain_controller, domain, user, password,
                                 lmhash, nthash)

    return requester.get_domainpolicy(source=source, queried_domain=queried_domain,
                                          resolve_sids=resolve_sids)

def get_gpttmpl(gpttmpl_path, domain_controller, domain, user, password=str(), lmhash=str(),
                nthash=str()):
    requester = GPORequester(domain_controller, domain, user, password,
                                 lmhash, nthash)

    return requester.get_gpttmpl(gpttmpl_path)

def get_netgpogroup(domain_controller, domain, user, password=str(), lmhash=str(),
                    nthash=str(), queried_gponame='*', queried_displayname=str(),
                    queried_domain=str(), ads_path=str(), resolve_sids=False):
    requester = GPORequester(domain_controller, domain, user, password,
                                 lmhash, nthash)

    return requester.get_netgpogroup(queried_gponame=queried_gponame,
                                         queried_displayname=queried_displayname,
                                         queried_domain=queried_domain,
                                         ads_path=ads_path,
                                         resolve_sids=resolve_sids)

def find_gpocomputeradmin(domain_controller, domain, user, password=str(), lmhash=str(),
                          nthash=str(), queried_computername=str(),
                          queried_ouname=str(), queried_domain=str(),
                          recurse=False):
    requester = GPORequester(domain_controller, domain, user, password,
                                 lmhash, nthash)

    return requester.find_gpocomputeradmin(queried_computername=queried_computername,
                                               queried_ouname=queried_ouname,
                                               queried_domain=queried_domain,
                                               recurse=recurse)

def find_gpolocation(domain_controller, domain, user, password=str(), lmhash=str(),
                     nthash=str(), queried_username=str(), queried_groupname=str(),
                     queried_localgroup=str(), queried_domain=str()):
    requester = GPORequester(domain_controller, domain, user, password,
                                 lmhash, nthash)
    return requester.find_gpolocation(queried_username=queried_username,
                                          queried_groupname=queried_groupname,
                                          queried_localgroup=queried_localgroup,
                                          queried_domain=queried_domain)

def invoke_checklocaladminaccess(target_computername, domain, user, password=str(),
                                 lmhash=str(), nthash=str()):
    misc = Misc(target_computername, domain, user, password, lmhash, nthash)

    return misc.invoke_checklocaladminaccess()

def invoke_userhunter(domain_controller, domain, user, password=str(),
                      lmhash=str(), nthash=str(), queried_computername=list(),
                      queried_computerfile=None, queried_computerfilter=str(),
                      queried_computeradspath=str(), unconstrained=False,
                      queried_groupname=str(), target_server=str(),
                      queried_username=str(), queried_useradspath=str(),
                      queried_userfilter=str(), queried_userfile=None,
                      threads=1, admin_count=False, allow_delegation=False,
                      stop_on_success=False, check_access=False, queried_domain=str(),
                      stealth=False, stealth_source=['dfs', 'dc', 'file'],
                      show_all=False, foreign_users=False):
    user_hunter = UserHunter(domain_controller, domain, user, password,
                             lmhash, nthash)
    
    return user_hunter.invoke_userhunter(queried_computername=queried_computername,
                                         queried_computerfile=queried_computerfile,
                                         queried_computerfilter=queried_computerfilter,
                                         queried_computeradspath=queried_computeradspath,
                                         unconstrained=unconstrained, queried_groupname=queried_groupname,
                                         target_server=target_server, queried_username=queried_username,
                                         queried_userfilter=queried_userfilter,
                                         queried_useradspath=queried_useradspath, queried_userfile=queried_userfile,
                                         threads=threads, admin_count=admin_count,
                                         allow_delegation=allow_delegation, stop_on_success=stop_on_success,
                                         check_access=check_access, queried_domain=queried_domain, stealth=stealth,
                                         stealth_source=stealth_source, show_all=show_all,
                                         foreign_users=foreign_users)

def invoke_processhunter(domain_controller, domain, user, password=str(),
                         lmhash=str(), nthash=str(), queried_computername=list(),
                         queried_computerfile=None, queried_computerfilter=str(),
                         queried_computeradspath=str(), queried_processname=list(),
                         queried_groupname=str(), target_server=str(),
                         queried_username=str(), queried_useradspath=str(),
                         queried_userfilter=str(), queried_userfile=None, threads=1,
                         stop_on_success=False, queried_domain=str(), show_all=False):
    process_hunter = ProcessHunter(domain_controller, domain, user, password,
                                   lmhash, nthash)

    return process_hunter.invoke_processhunter(queried_computername=queried_computername,
                                               queried_computerfile=queried_computerfile,
                                               queried_computerfilter=queried_computerfilter,
                                               queried_computeradspath=queried_computeradspath,
                                               queried_processname=queried_processname,
                                               queried_groupname=queried_groupname,
                                               target_server=target_server, queried_username=queried_username,
                                               queried_userfilter=queried_userfilter,
                                               queried_useradspath=queried_useradspath, queried_userfile=queried_userfile,
                                               threads=threads, stop_on_success=stop_on_success,
                                               queried_domain=queried_domain, show_all=show_all)

def invoke_eventhunter(domain_controller, domain, user, password=str(),
                       lmhash=str(), nthash=str(), queried_computername=list(),
                       queried_computerfile=None, queried_computerfilter=str(),
                       queried_computeradspath=str(), queried_groupname=str(),
                       target_server=str(), queried_username=str(),
                       queried_useradspath=str(), queried_userfilter=str(),
                       queried_userfile=None, threads=1, queried_domain=str(),
                       search_days=3):
    event_hunter = EventHunter(domain_controller, domain, user, password,
                                   lmhash, nthash)

    return event_hunter.invoke_eventhunter(queried_computername=queried_computername,
                                           queried_computerfile=queried_computerfile,
                                           queried_computerfilter=queried_computerfilter,
                                           queried_computeradspath=queried_computeradspath,
                                           queried_groupname=queried_groupname,
                                           target_server=target_server,
                                           queried_userfilter=queried_userfilter,
                                           queried_username=queried_username,
                                           queried_useradspath=queried_useradspath,
                                           queried_userfile=queried_userfile,
                                           search_days=search_days,
                                           threads=threads, queried_domain=queried_domain)

