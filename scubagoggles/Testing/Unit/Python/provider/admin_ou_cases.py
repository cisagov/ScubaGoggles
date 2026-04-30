"""
Parametrized test case data for admin/OU Provider methods.
"""

from google.auth.exceptions import RefreshError

# Test cases for Provider.get_privileged_users(); see GWS.COMMONCONTROLS.6.1
# (cisagov/ScubaGoggles#589).  Each case provides the responses from the
# directory users, roles, and roleAssignments APIs (in that order, since
# users are listed first to capture isAdmin Super Admins) and the expected
# output.
GET_PRIVILEGED_USERS_CASES = [
    # Super Admin detected via the Directory user.isAdmin flag.  This
    # mirrors how get_super_admins() identifies super admins and ensures
    # we don't miss them when the Super Admin role's privileges aren't
    # reported in rolePrivileges (Google identifies that role with
    # isSuperAdminRole instead).
    {
        "user_list": [
            {
                "id": "user-1",
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": "/",
                "isAdmin": True,
            },
            {
                "id": "user-2",
                "primaryEmail": "user2@example.org",
                "orgUnitPath": "/",
                "isAdmin": False,
            },
        ],
        "role_list": [],
        "assignment_list": [],
        "raises": None,
        "expected": {
            "privileged_users": [
                {
                    "primaryEmail": "admin1@example.org",
                    "orgUnitPath": "",
                },
            ],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # Privileged delegated admin detected by holding a role whose
    # privileges intersect HIGHLY_PRIVILEGED_PRIVILEGES.  The non-
    # privileged "helpdesk" role assignment is ignored.
    {
        "user_list": [
            {
                "id": "user-1",
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": "/Admins",
                "isAdmin": False,
                "isDelegatedAdmin": True,
            },
            {
                "id": "user-2",
                "primaryEmail": "user2@example.org",
                "orgUnitPath": "/",
                "isAdmin": False,
                "isDelegatedAdmin": False,
            },
        ],
        "role_list": [
            {
                "roleId": "role-users",
                "rolePrivileges": [
                    {"privilegeName": "USERS_ALL", "serviceId": "all"},
                ],
            },
            {
                "roleId": "role-helpdesk",
                "rolePrivileges": [
                    {"privilegeName": "USERS_VIEW", "serviceId": "all"},
                ],
            },
        ],
        "assignment_list": [
            {
                "assigneeType": "USER",
                "assignedTo": "user-1",
                "roleId": "role-users",
                "scopeType": "CUSTOMER",
            },
            {
                "assigneeType": "USER",
                "assignedTo": "user-2",
                "roleId": "role-helpdesk",
                "scopeType": "CUSTOMER",
            },
        ],
        "raises": None,
        "expected": {
            "privileged_users": [
                {
                    "primaryEmail": "admin1@example.org",
                    "orgUnitPath": "Admins",
                },
            ],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # Built-in Super Admin role is identified by isSuperAdminRole=True
    # rather than by privilegeName.  A user assigned this role (but
    # without isAdmin set on their User record - which can happen for
    # service-specific super admins in some tenants) must still be
    # detected.
    {
        "user_list": [
            {
                "id": "user-1",
                "primaryEmail": "super1@example.org",
                "orgUnitPath": "/",
                "isAdmin": False,
            },
        ],
        "role_list": [
            {
                "roleId": "role-super",
                "roleName": "_SEED_ADMIN_ROLE",
                "isSuperAdminRole": True,
                "rolePrivileges": [],
            },
        ],
        "assignment_list": [
            {
                "assigneeType": "USER",
                "assignedTo": "user-1",
                "roleId": "role-super",
                "scopeType": "CUSTOMER",
            },
        ],
        "raises": None,
        "expected": {
            "privileged_users": [
                {
                    "primaryEmail": "super1@example.org",
                    "orgUnitPath": "",
                },
            ],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # Built-in User Management Admin role name should be treated as privileged
    # even if returned rolePrivileges don't include expected identifiers.
    {
        "user_list": [
            {
                "id": "user-1",
                "primaryEmail": "test.admin@scubagws.org",
                "orgUnitPath": "/Devesh's Test OU",
                "isAdmin": False,
                "isDelegatedAdmin": True,
            },
        ],
        "role_list": [
            {
                "roleId": "role-user-mgmt",
                "roleName": "User Management Admin",
                "rolePrivileges": [
                    {"privilegeName": "SOME_TENANT_SPECIFIC_VALUE", "serviceId": "all"},
                ],
            },
        ],
        "assignment_list": [
            {
                "assigneeType": "USER",
                "assignedTo": "user-1",
                "roleId": "role-user-mgmt",
                "scopeType": "CUSTOMER",
            },
        ],
        "raises": None,
        "expected": {
            "privileged_users": [
                {
                    "primaryEmail": "test.admin@scubagws.org",
                    "orgUnitPath": "Devesh's Test OU",
                },
            ],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # User detected by both isAdmin and a role assignment is reported
    # only once (deduplicated by primaryEmail).
    {
        "user_list": [
            {
                "id": "user-1",
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": "/",
                "isAdmin": True,
            },
        ],
        "role_list": [
            {
                "roleId": "role-a",
                "rolePrivileges": [
                    {"privilegeName": "USERS_ALL", "serviceId": "all"},
                ],
            },
        ],
        "assignment_list": [
            {
                "assigneeType": "USER",
                "assignedTo": "user-1",
                "roleId": "role-a",
                "scopeType": "CUSTOMER",
            },
        ],
        "raises": None,
        "expected": {
            "privileged_users": [
                {
                    "primaryEmail": "admin1@example.org",
                    "orgUnitPath": "",
                },
            ],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # Group assignments to a privileged role are ignored (only USER
    # assigneeType is considered for CC 6.1).
    {
        "user_list": [],
        "role_list": [
            {
                "roleId": "role-super",
                "isSuperAdminRole": True,
                "rolePrivileges": [],
            },
        ],
        "assignment_list": [
            {
                "assigneeType": "GROUP",
                "assignedTo": "group-1",
                "roleId": "role-super",
                "scopeType": "CUSTOMER",
            },
        ],
        "raises": None,
        "expected": {
            "privileged_users": [],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # If role metadata is sparse or non-standard, delegated admins should
    # still be included via users.isDelegatedAdmin fallback.
    {
        "user_list": [
            {
                "id": "user-1",
                "primaryEmail": "test.admin@scubagws.org",
                "orgUnitPath": "/Devesh's Test OU",
                "isAdmin": False,
                "isDelegatedAdmin": True,
            },
        ],
        "role_list": [],
        "assignment_list": [],
        "raises": None,
        "expected": {
            "privileged_users": [
                {
                    "primaryEmail": "test.admin@scubagws.org",
                    "orgUnitPath": "Devesh's Test OU",
                },
            ],
            "privileged_users_error": None,
        },
        "expect_success_call": True,
    },
    # API failure.  An error is reported in privileged_users_error so the
    # rego treats the policy as NoSuchEvent rather than passing silently.
    {
        "user_list": None,
        "role_list": None,
        "assignment_list": None,
        "raises": Exception("API error"),
        "expected": {
            "privileged_users": [],
            "privileged_users_error": "API error",
        },
        "expect_success_call": False,
    },
]

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
    # Root OU missing and "organizationUnits" is empty
    {
        "api_response": { "organizationUnits": [] },
        "expected": "",
        "raises": None,
        "expect_success_call": True,
    },
    # "organizationUnits" key is present but root OU, "/", is missing
    {
        "api_response": {
            "organizationUnits": [
                { "orgUnitPath": "/Sub-OU1", "name": "Sub OU 1" },
                { "orgUnitPath": "/Sub-OU2", "name": "Sub OU 2" },
            ]
        },
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
