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
services['reports'] = build('admin', 'reports_v1', credentials=creds)
services['directory'] = build('admin', 'directory_v1', credentials=creds)
services['groups'] = build('groupssettings', 'v1', credentials=creds)

class ProviderTests(unittest.TestCase):
    """Test cases for provider"""

    def test_is_dict(self):
        gsa_out = get_super_admins(services["directory"], "C03ymv5su")
        self.assertIsInstance(gsa_out,dict)

    def test_contains_list(self):
        gsa_out = get_super_admins(services["directory"], "C03ymv5su")
        self.assertIsInstance(gsa_out['super_admins'],list)

#unit_argv = [sys.argv[0]] + unittestArgs
if __name__ == '__main__':
    unittest.main()
