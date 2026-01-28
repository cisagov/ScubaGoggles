"""
Parametrized test case data for DNS Provider methods,
e.g., SPF, DKIM, DMARC
"""

from scubagoggles.provider import SELECTORS

GET_SPF_RECORDS_CASES = [
    # Multiple domains with SPF records returned
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
                        "query_result": "Query returned 1 txt records",
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
                        "query_result": "Query returned 1 txt records",
                        "query_answers": ["v=spf1 include:_spf.google.com ~all"],
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
    # DMARC record missiong for subdomain, but present on parent domain
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
        {"example.com"},
        {
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
        },
        [
            {
                "domain": "example.com",
                "rdata": [],
                "log": [
                    {
                        "query_name": "_dmarc.example.com",
                        "query_method": "traditional",
                        "query_result": "Query returned NXDOMAIN",
                        "query_answers": [],
                    },
                    {
                        "query_name": "_dmarc.example.com",
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
        "expected_calls": True
    },
    # Case where no verified domains exist
    {
        "base_domains": [],
        "alias_domains": [],
        "spf_output": [],
        "dkim_output": [],
        "dmarc_output": [],
        "expected_calls": False
    },
]
