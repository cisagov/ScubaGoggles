"""
Parametrized test case data for admin/OU Provider methods.
"""

from google.auth.exceptions import RefreshError

GET_SUPER_ADMIN_CASES = [
    # Multiple super admins returned
    {
        "user_list": [
            {
                "orgUnitPath": "/",
                "primaryEmail": "firstlast@example.com",
            },
            {
                "orgUnitPath": "/Sub-OU",
                "primaryEmail": "firstlast1@example.com",
            }
        ],
        "get_list_raises": None,
        "expected": {
            "super_admins": [
                {
                    "primaryEmail": "firstlast@example.com",
                    "orgUnitPath": "",
                },
                {
                    "primaryEmail": "firstlast1@example.com",
                    "orgUnitPath": "Sub-OU",
                }
            ]
        },
        "expect_success_call": True,
    },
    # API raises generic exception
    {
        "user_list": None,
        "get_list_raises": Exception("API error"),
        "expected": {
            "super_admins": []
        },
        "expect_success_call": False,
    },
    # API raises RefreshError
    {
        "user_list": None,
        "get_list_raises": RefreshError("access_denied: Requested client not authorized"),
        "expected": {
            "super_admins": []
        },
        "expect_success_call": False,
    },
    # Empty user list returned
    {
        "user_list": [],
        "get_list_raises": None,
        "expected": {
            "super_admins": []
        },
        "expect_success_call": True,
    },
]

GET_OU_CASES = [
    # Multiple OUs returned
    {
        "api_response": {
            "organizationUnits": [
                { "orgUnitPath": "/", "name": "Root OU" },
                { "orgUnitPath": "/Sub-OU1", "name": "Sub OU 1" },
                { "orgUnitPath": "/Sub-OU2", "name": "Sub OU 2" },
            ]
        },
        "expected": {
            "organizationUnits": [
                { "orgUnitPath": "/", "name": "Root OU" },
                { "orgUnitPath": "/Sub-OU1", "name": "Sub OU 1" },
                { "orgUnitPath": "/Sub-OU2", "name": "Sub OU 2" },
            ]
        },
        "raises": None,
        "expect_success_call": True,
    },
    # No OUs returned
    {
        "api_response": {},
        "expected": {},
        "raises": None,
        "expect_success_call": True,
    },
    # API raises exception
    {
        "api_response": None,
        "expected": {},
        "raises": Exception("API error"),
        "expect_success_call": False,
    },
]

GET_TOPLEVEL_OU_CASES = [
    # Root OU found
    {
        "api_response": {
            "organizationUnits": [
                { "orgUnitPath": "/", "name": "Root OU" },
                { "orgUnitPath": "/Sub-OU1", "name": "Sub OU 1" },
            ]
        },
        "expected": "Root OU",
        "raises": None,
        "expect_success_call": True,
    },
    # Root OU missing
    {
        "api_response": { "organizationUnits": [] },
        "expected": "",
        "raises": None,
        "expect_success_call": True,
    },
    # API raises exception
    {
        "api_response": None,
        "expected": "",
        "raises": Exception("API error"),
        "expect_success_call": False,
    },
    # API raises RefreshError
    {
        "api_response": None,
        "expected": "",
        "raises": RefreshError("access_denied: Requested client not authorized"),
        "expect_success_call": False,
    },
]

GET_TENANT_INFO_CASES = [
    # Primary domain found
    {
        "customer_execute": { "id": "C012345" },
        "customer_side_effect": None,
        "domains": [{ "domainName": "example.com", "isPrimary": True }],
        "expected": {
            "ID": "C012345",
            "domain": "example.com",
            "topLevelOU": "Root OU",
        },
        "expect_warning": False,
    },
    # No primary domain found
    {
        "customer_execute": { "id": "C012345" },
        "customer_side_effect": None,
        "domains": [{ "domainName": "example.com", "isPrimary": False }],
        "expected": {
            "ID": "C012345",
            "domain": "Error Retrieving",
            "topLevelOU": "Root OU",
        },
        "expect_warning": False,
    },
    # get customers throws Exception
    {
        "customer_execute": None,
        "customer_side_effect": Exception("API error"),
        "domains": [ { "domainName": "example.com", "isPrimary": True }],
        "expected": {
            "ID": "",
            "domain": "Error Retrieving",
            "topLevelOU": "Root OU",
        },
        "expect_warning": True,
    },
    # get customers throws RefreshError
    {
        "customer_execute": None,
        "customer_side_effect": RefreshError(
            "access_denied: Requested client not authorized"
        ),
        "domains": [ { "domainName": "example.com", "isPrimary": True }],
        "expected": {
            "ID": "",
            "domain": "Error Retrieving",
            "topLevelOU": "Root OU",
        },
        "expect_warning": True,
    },
]
