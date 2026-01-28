"""
Parametrize test case data for domain-related Provider methods.
"""

LIST_DOMAINS_CASES = [
    (
        {
            "domains": [
                {"domainName": "example.com", "verified": True},
                {"domainName": "test.org", "verified": False},
            ]
        },
        [
            {"domainName": "example.com", "verified": True},
            {"domainName": "test.org", "verified": False},
        ],
    ),
    (
        { "domains": [] },
        [],
    ),
    (
        {},
        [],
    ),
]

LIST_ALIAS_DOMAINS_CASES = [
    (
        {
            "domainAliases": [
                {"domainAliasName": "alias1.com", "verified": True},
                {"domainAliasName": "alias2.org", "verified": False},
            ]
        },
        [
            {"domainAliasName": "alias1.com", "verified": True},
            {"domainAliasName": "alias2.org", "verified": False},
        ],
    ),
    (
        { "domainAliases": [] },
        [],
    ),
    (
        {},
        [],
    ),
]