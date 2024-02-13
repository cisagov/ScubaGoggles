#Todo:
#provider, orchestrator, auth, main, robust_dns, run_rego, utils, reporter.py, md_parser.py
import unittest
import sys
import os
from pathlib import Path
from scubagoggles.provider import Provider
from scubagoggles.auth import gws_auth
from scubagoggles.main import get_gws_args
from scubagoggles.orchestrator import gws_products, run_gws_providers, rego_eval, pluralize, run_reporter, run_cached, start_automation, generate_summary
from googleapiclient.discovery import build
import argparse


#creds = gws_auth((Path.cwd() / "../credentials.json").resolve(), "amart24@scubagws.org")
creds = gws_auth("../credentials.json")

services = {}
services['directory'] = build('admin', 'directory_v1', credentials=creds)
services['reports'] = build('admin', 'reports_v1', credentials=creds)
services['groups'] = build('groupssettings','v1', credentials=creds)

#Create instance of provider to use for unit testing
provider = Provider(services, 'C03ymv5su')

class TestArgs:
    def __init__(self):
        self.scuba_cmd='gws'
        self.baselines=['sites']
        self.outputpath='../'
        self.credentials='../credentials.json'
        self.subjectemail=None
        self.customerid='my_customer'
        self.opapath='../'
        self.regopath='../rego'
        self.documentpath='../baselines'
        self.runcached=False
        self.skipexport=False
        self.outputfoldername='GWSBaselineConformance'
        self.outputproviderfilename='ProviderSettingsExport'
        self.outputregofilename='TestResults'
        self.outputreportfilename='BaselineReports'
        self.omitsudo=False
        self.quiet=False
        self.debug=False

# class ProviderTests(unittest.TestCase):
#     """Test cases for provider"""

#     # def list_domains(self) -> list:
#     #   print("test")

#     # def test_get_spf_records(self):
#     #     print("test")
    
#     # def test_get_dkim_records(self):
#     #     print("test")

#     # def test_get_dmarc_records(self):
#     #     print("test")

#     # def test_get_dnsinfo(self):
#     #     print("test")

#     def test_get_super_admins_is_dict(self):
#         gsa_out = provider.get_super_admins()
#         self.assertIsInstance(gsa_out,dict)

#     def test_get_super_admins_contains_list(self):
#         gsa_out = provider.get_super_admins()
#         self.assertIsInstance(gsa_out['super_admins'],list)

#     def test_get_ous(self):
#         ou_out = provider.get_ous()
#         self.assertIsInstance(ou_out,dict)

#     def test_get_toplevel_ou(self):
#         tlou_out = provider.get_toplevel_ou()
#         self.assertIsInstance(tlou_out,str)

#     def test_get_tenant_info(self):
#         ti_out = provider.get_tenant_info()
#         self.assertIsInstance(ti_out,dict)

#     def test_get_gws_logs(self):
#         logs_out = provider.get_gws_logs(gws_products()["gws_baselines"],"CHANGE_APPLICATION_SETTING")
#         self.assertIsInstance(logs_out,dict)

#     def test_get_group_settings(self):
#         gs_out = provider.get_tenant_info()
#         self.assertIsInstance(gs_out,dict)

#     def test_call_gws_providers(self):
#         gp_out = provider.call_gws_providers(gws_products()["gws_baselines"], True)
#         self.assertIsInstance(gp_out,dict)

class OrchestratorTests(unittest.TestCase):
    """Test cases for orchestrator"""

    def test_gws_products(self):
        prod_out = gws_products()
        self.assertIsInstance(prod_out,dict)

    #test takes too long to run for developing. Uncomment when unit tests are complete. Runs provider. 
    def test_run_gws_providers(self):
        test_args = TestArgs()
        run_gws_providers(test_args, services)
        print(os.listdir('../'))
        self.assertEqual(1,1)

    # def test_rego_eval(self):
    #     #rego_eval produces a test results json file 
    #     test_args = TestArgs()
    #     failure = False
    #     try:
    #         rego_eval(test_args)
    #     except:
    #         failure = true
    #     self.assertEqual(failure, False)   

#     def test_pluralize(self): TODO: unit test probably not needed for this funciton
#         print("test")

#     def test_run_reporter(self):
#         print("test")

#     def test_run_cached(self):
#         print("test")

#     def test_start_automation(self):
#         print("test")
        
# class AuthTests(unittest.TestCase):
#     """Test cases for auth"""

#     def test_gws_auth(self):
#         print("test")
        
# class MainTests(unittest.TestCase):
#     """Test cases for main"""

#     def test_get_gws_args(self):
#         print("test")

#     def test_dive(self):
#         print("test")

# class RobustDNSTests(unittest.TestCase):
#     """Test cases for RobustDNS"""

#     def test_query(self):
#         print("test")

#     def test_traditional_query(self):
#         print("test")

#     def test_get_doh_server(self):
#         print("test")

#     def test_doh_query(self):
#         print("test")
        
# class RunRego(unittest.TestCase):
#     """Test cases for RunRego"""

#     def test_opa_eval(self):
#         print("test")
        
# class Utils(unittest.TestCase):
#     """Test cases for Utils"""

#     def test_create_subset_inverted_dict(self):
#         print("test")

#     def test_create_key_to_list(self):
#         print("test")

#     def test_merge_dicts(self):
#         print("test")

#     def test_rel_abs_path(self):
#         print("test")
        
# class Reporter(unittest.TestCase):
#     """Test cases for Reporter"""

#     def test_get_test_result(self):
#         print("test")

#     def test_create_html_table(self):
#         print("test")

#     def test_build_front_page_html(self):
#         print("test")

#     def test_build_report_html(self):
#         print("test")
        
#     def test_rego_json_to_html(self):
#         print("test")
        
# class MdParser(unittest.TestCase):
#     """Test cases for MdParser"""

#     def test_read_baseline_docs(self):
#         print("test")

if __name__ == '__main__':
    unittest.main()
