#Todo:
#provider, orchestrator, auth, main, robust_dns, run_rego, utils, reporter.py, md_parser.py
import unittest
import sys
import os
from pathlib import Path
from provider import get_spf_records, get_dkim_records, get_dmarc_records, get_super_admins, get_dnsinfo, get_ous, get_toplevel_ou, get_tenant_info, get_gws_logs, get_group_settings, call_gws_providers
from auth import gws_auth
from googleapiclient.discovery import build
import argparse

creds = gws_auth((Path.cwd() / "../credentials.json").resolve())

services = {}
services['directory'] = build('admin', 'directory_v1', credentials=creds)

class ProviderTests(unittest.TestCase):
    """Test cases for provider"""

    # def test_get_spf_records(self):
    #     print("test")
    
    # def test_get_dkim_records(self):
    #     print("test")

    # def test_get_dmarc_records(self):
    #     print("test")

    # def test_get_dnsinfo(self):
    #     print("test")

    def test_get_super_admins_is_dict(self):
        gsa_out = get_super_admins(services["directory"], "C03ymv5su")
        self.assertIsInstance(gsa_out,dict)

    def test_get_super_admins_contains_list(self):
        gsa_out = get_super_admins(services["directory"], "C03ymv5su")
        self.assertIsInstance(gsa_out['super_admins'],list)

    # def test_get_ous(self):
    #     print("test")

    # def test_get_toplevel_ou(self):
    #     print("test")

    # def test_get_tenant_info(self):
    #     print("test")

    # def test_get_gws_logs(self):
    #     print("test")

    # def test_get_group_settings(self):
    #     print("test")

    # def test_call_gws_providers(self):
    #     print("test")
        
# class OrchestratorTests(unittest.TestCase):
#     """Test cases for orchestrator"""

#     def test_gws_products(self):
#         print("test")

#     def test_run_gws_providers(self):
#         print("test")

#     def test_rego_eval(self):
#         print("test")

#     def test_pluralize(self):
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
