"""
Parametrized test case data for DNS Provider methods,
e.g., SPF, DKIM, DMARC
"""

from scubagoggles.provider import SELECTORS

GET_SPF_RECORDS_CASES = [
    # Multiple domains with soft fail SPF records returned
    (
        { "example.com" },
        {
            "example.com": {
                "answers": ["v=spf1 include:_spf.google.com ~all"],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 SPF record",
                        "query_answers": ["v=spf1 include:_spf.google.com ~all"],
                    }
                ],
            }
        },
        [
            {
                "domain": "example.com",
                "rdata": ["v=spf1 include:_spf.google.com ~all"],
                "log": [
                    {
                        "query_name": "example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 SPF record",
                        "query_answers": ["v=spf1 include:_spf.google.com ~all"],
                    }
                ],
            }
        ]
    ),
        # Multiple domains with hard fail SPF records returned
    (
        { "example.com" },
        {
            "example.com": {
                "answers": ["v=spf1 include:_spf.google.com -all"],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 SPF record",
                        "query_answers": ["v=spf1 include:_spf.google.com -all"],
                    }
                ],
            }
        },
        [
            {
                "domain": "example.com",
                "rdata": ["v=spf1 include:_spf.google.com -all"],
                "log": [
                    {
                        "query_name": "example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 SPF record",
                        "query_answers": ["v=spf1 include:_spf.google.com -all"],
                    }
                ],
            }
        ]
    ),
    # Non-existant domain (NXDOMAIN)
    (
        { "example.com" },
        {
            "example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            }
        },
        [
            {
                "domain": "example.com",
                "rdata": [],
                "log": [
                    {
                        "query_name": "example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            },
        ]
    ),
]

GET_DKIM_RECORDS_CASES = [
    # DKIM found on first selector
    (
        { "example.com" },
        {
            f"{SELECTORS[0]}._domainkey.example.com": {
                "answers": [
                    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                ],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": [
                            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                        ],
                    },
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": [
                            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                        ],
                    },
                ],
            },
        },
        [
            {
            "domain": "example.com",
                "rdata": [
                    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                ],
                "log": [
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": [
                            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                        ],
                    },
                ],
            }
        ],
    ),
    # DKIM found on second selector
    (
        { "example.com" },
        {
            f"{SELECTORS[0]}._domainkey.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                ],
            },
            f"{SELECTORS[1]}._domainkey.example.com": {
                "answers": [
                    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                ],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": [
                            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                        ],
                    },
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": [
                            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                        ],
                    },
                ],
            },
        },
        [
            {
                "domain": "example.com",
                "rdata": [
                    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                ],
                "log": [
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": [
                            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
                        ],
                    },
                ],
            }
        ]
    ),
    # No DKIM across all selectors
    (
        { "example.com" },
        {
            f"{SELECTORS[0]}._domainkey.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                ],
            },
            f"{SELECTORS[1]}._domainkey.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                ],
            },
            f"{SELECTORS[2]}._domainkey.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": f"{SELECTORS[2]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[2]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                ],
            },
        },
        [
            {
                "domain": "example.com",
                "rdata": [],
                "log": [
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[0]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[1]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[2]}._domainkey.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": f"{SELECTORS[2]}._domainkey.example.com",
                        "query_method": "DoH",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                ]
            }
        ]
    )
]

GET_DMARC_RECORDS_CASES = [
    # DMARC record exists
    (
        { "example.com" },
        {
            "_dmarc.example.com": {
                "answers": ["v=DMARC1; p=none"],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": ["v=DMARC1; p=none"],
                    },
                ]
            },
        },
        [
            {
                "domain": "example.com",
                "rdata": ["v=DMARC1; p=none"],
                "log": [
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": ["v=DMARC1; p=none"],
                    },
                ],
            }
        ]
    ),
    # DMARC record missing for subdomain, but present on parent domain
    (
        {"sub.example.com"},
        {
            "_dmarc.sub.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "_dmarc.sub.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            },
            "_dmarc.example.com": {
                "answers": ["v=DMARC1; p=reject"],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": ["v=DMARC1; p=reject"],
                    }
                ],
            },
        },
        [
            {
                "domain": "sub.example.com",
                "rdata": ["v=DMARC1; p=reject"],
                "log": [
                    {
                        "query_name": "_dmarc.sub.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned 1 txt records",
                        "query_answers": ["v=DMARC1; p=reject"],
                    },
                ],
            }
        ],
    ),
    # No DMARC records found for either sub/parent domain
    (
        {"sub.example.com"},
        {
            "_dmarc.sub.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "_dmarc.sub.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            },
            "_dmarc.example.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            },
            "_dmarc.com": {
                "answers": [],
                "nxdomain": False,
                "log_entries": [
                    {
                        "query_name": "_dmarc.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            },
        },
        [
            {
                "domain": "sub.example.com",
                "rdata": [],
                "log": [
                    {
                        "query_name": "_dmarc.sub.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": "_dmarc.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    }
                ],
            }
        ],
    )
]

GET_DNSINFO_CASES = [
    # Case with verified base and alias domains
    {
        "base_domains": [
            {"domainName": "example.com", "verified": True},
            {"domainName": "unverified.com", "verified": False},
        ],
        "alias_domains": [
            {"domainAliasName": "alias.com", "verified": True}
        ],
        "spf_output": [
            {
                "domain": "example.com",
                "rdata": ["v=spf1 include:_spf.google.com ~all"],
                "log": []
            }
        ],
        "dkim_output": [
            {
                "domain": "example.com",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."],
                "log": []
            },
        ],
        "dmarc_output": [
            {
                "domain": "example.com",
                "rdata": ["v=DMARC1; p=none"],
                "log": []
            },
            {
                "domain": "alias.com",
                "rdata": ["v=DMARC1; p=none"],
                "log": []
            }
        ],
        "expected_calls": True,
        "expected_base_domains": ["example.com"],
        "expected_alias_domains": ["alias.com"]
    },
    # Case where no verified base domains exist but verified alias domains exist
    {
        "base_domains": [
            {"domainName": "unverified.com", "verified": False},
        ],
        "alias_domains": [
            {"domainAliasName": "alias.com", "verified": True}
        ],
        "spf_output": [],
        "dkim_output": [],
        "dmarc_output": [
            {
                "domain": "alias.com",
                "rdata": ["v=DMARC1; p=none"],
                "log": []
            }
        ],
        "expected_calls": True,
        "expected_base_domains": [],
        "expected_alias_domains": ["alias.com"],
    },
    # Case where verified base domains exist but no verified alias domains exist
    {
        "base_domains": [
            {"domainName": "example.com", "verified": True},
        ],
        "alias_domains": [
            {"domainAliasName": "unverified.com", "verified": False},
        ],
        "spf_output": [
            {
                "domain": "example.com",
                "rdata": ["v=spf1 include:_spf.google.com ~all"],
                "log": []
            }
        ],
        "dkim_output": [
            {
                "domain": "example.com",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."],
                "log": []
            },
        ],
        "dmarc_output": [
            {
                "domain": "example.com",
                "rdata": ["v=DMARC1; p=none"],
                "log": []
            }
        ],
        "expected_calls": True,
        "expected_base_domains": ["example.com"],
        "expected_alias_domains": [],
    },
    # Case where no verified domains exist
    {
        "base_domains": [],
        "alias_domains": [],
        "spf_output": [],
        "dkim_output": [],
        "dmarc_output": [],
        "expected_calls": False,
        "expected_base_domains": [],
        "expected_alias_domains": []
    },
]

PARSE_DMARC_RECORD_CASES = [
    # Standard case
    (
        ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com;"],
        {"v": "DMARC1", "p": "reject", "rua": "mailto:dmarc@example.com"}
    ),
    # Ignore whitespace around "=" and ";"
    (
        ["v\t=  DMARC1  \t;p=reject;"],
        {"v": "DMARC1", "p": "reject"}
    ),
    # Discard all if multiple DMARC records are returned
    (
        ["v=DMARC1;", "v=DMARC1;"],
        {}
    ),
    # Ignore non-DMARC txt records
    (
        ["v=DMARC1;", "domain-verification=abc"],
        {"v": "DMARC1"}
    ),
    # Require "v" tag to be first
    (
        ["p=reject; v=DMARC1;"],
        {}
    ),
    # Ignore invalid DMARC versions
    (
        ["v=DMARC0;"],
        {}
    ),
    # Missing ";" deliminator
    (
        ["v=DMARC1 p=reject;"],
        {}
    ),
    # Discard if duplicate tags
    (
        ["v=DMARC1;p=reject;p=reject"],
        {}
    ),
]
