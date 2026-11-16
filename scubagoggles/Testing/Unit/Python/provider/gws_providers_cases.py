"""
Parametrized test case data for call_gws_providers submethods.
"""

COLLECT_ORGANIZATIONAL_UNITS_CASES = [
    # Multiple OUs returned; top OU and empty OU id included in names
    {
        "top_ou": "Root OU",
        "ous_response": {
            "organizationUnits": [
                {"orgUnitPath": "/", "name": "Root OU"},
                {"orgUnitPath": "/Sub-OU1", "name": "Sub OU 1"},
            ]
        },
        "get_ous_raises": None,
        "expect_warning": False,
        "expected_keys": ["organizational_units", "organizational_unit_names"],
        "expected_ou_names": {"", "Root OU", "Sub OU 1"},
    },
    # Empty organizationUnits list; still includes top OU and empty OU id
    {
        "top_ou": "Root OU",
        "ous_response": {"organizationUnits": []},
        "get_ous_raises": None,
        "expect_warning": False,
        "expected_keys": ["organizational_units", "organizational_unit_names"],
        "expected_ou_names": {"", "Root OU"},
    },
    # get_ous raises; warning issued and keys may be missing
    {
        "top_ou": "Root OU",
        "ous_response": None,
        "get_ous_raises": Exception("OU API error"),
        "expect_warning": True,
        "expected_keys": [],
        "expected_ou_names": None,
    },
]

COLLECT_GWS_LOGS_CASES = [
    # Successful log collection for a single product/event
    {
        "products": ["gemini"],
        "get_gws_logs_side_effect": [
            {"gemini": [{"id": "log1"}]},
            {"gemini": [{"id": "log2"}]},
            {"gemini": [{"id": "log3"}]},
        ],
        "get_gws_logs_raises": None,
        "expect_warning": False,
        "expect_success_call": True,
        "expect_unsuccessful_call": False,
        "expected": {
            "gemini": [
                {"id": "log1"},
                {"id": "log2"},
                {"id": "log3"},
            ]
        },
    },
    # get_gws_logs raises; warning issued and unsuccessful call tracked
    {
        "products": ["gmail"],
        "get_gws_logs_side_effect": None,
        "get_gws_logs_raises": Exception("logs API error"),
        "expect_warning": True,
        "expect_success_call": False,
        "expect_unsuccessful_call": True,
        "expected": {"gmail": []},
    },
]

ASSEMBLE_PROVIDER_ITEMS_CASES = [
    # Gmail product includes DNS info; no commoncontrols extras
    {
        "product_to_logs": {"gmail": [{"id": "g1"}]},
        "product_to_items": {},
        "tenant_info": {"ID": "t1", "domain": "example.com", "topLevelOU": "Root"},
        "dns_info": {"spf_records": [], "dkim_records": [], "dmarc_records": []},
        "group_settings": {"group_settings": []},
        "include_commoncontrols": False,
        "get_tenant_info_raises": None,
        "expect_warning": False,
        "expected_log_keys": ["gmail_logs"],
        "expect_dns": True,
        "expect_commoncontrols": False,
    },
    # Commoncontrols product includes admin/SSO/license data
    {
        "product_to_logs": {"commoncontrols": [{"id": "cc1"}]},
        "product_to_items": {},
        "tenant_info": {"ID": "t1", "domain": "example.com", "topLevelOU": "Root"},
        "dns_info": None,
        "group_settings": {"group_settings": []},
        "include_commoncontrols": True,
        "get_tenant_info_raises": None,
        "expect_warning": False,
        "expected_log_keys": ["commoncontrols_logs"],
        "expect_dns": False,
        "expect_commoncontrols": True,
    },
    # Exception during assembly issues a warning
    {
        "product_to_logs": {"chat": [{"id": "c1"}]},
        "product_to_items": {},
        "tenant_info": None,
        "dns_info": None,
        "group_settings": None,
        "include_commoncontrols": False,
        "get_tenant_info_raises": Exception("tenant error"),
        "expect_warning": True,
        "expected_log_keys": ["chat_logs"],
        "expect_dns": False,
        "expect_commoncontrols": False,
    },
]
