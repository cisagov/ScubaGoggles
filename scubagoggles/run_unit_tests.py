# Non-rego Unit Tests for ScubaGoggles

#auth
#main
#orcehstrator
#provider
#robust_dns
#run_rego
#utils

from provider import get_super_admins, get_ous, get_toplevel_ou, get_tenant_info, get_gws_logs, get_group_settings, call_gws_providers # partial list of provider.py functions
from auth import gws_auth
from googleapiclient.discovery import build

creds = gws_auth("../credentials.json", "gbrown@scubagws.org")
services = {}
services['reports'] = build('admin', 'reports_v1', credentials=creds)
services['directory'] = build('admin', 'directory_v1', credentials=creds)
services['groups'] = build('groupssettings', 'v1', credentials=creds)

def test_get_super_admins1(service, customer_id): #Given a true super admin
    get_super_admins(service, customer_id)

def test_get_super_admins2(service, customer_id): #Given a non super admin
    get_super_admins(service, customer_id)

def test_get_super_admins3(service, customer_id): #Given a non-existent user
    get_super_admins(service, customer_id)

def main():
    test_get_super_admins1(services["directory"], "794320852228-324qfr3cihsitfr2efm79kb99jq9g02e.apps.googleusercontent.com") #Grant
    test_get_super_admins1(services["directory"], "1057411921045-pl8io0gsv9h9hk2fh2pik55ntn5e4a1p.apps.googleusercontent.com") #Nestor
    test_get_super_admins1(services["directory"], "blahblahnotrealuser") 
