"""
Parametrized test case data for license data Provider methods.
"""

GET_LICENSE_DATA_CASES = [
    # Aggregates SKU assignment counts across a single product response.
    {
        "product_ids": ["Google-Apps"],
        "domains": [{"domainName": "example.com", "isPrimary": True}],
        "product_responses": {
            "Google-Apps": [
                {
                    "items": [
                        {
                            "skuId": "sku-1",
                            "skuName": "Google Workspace Business Starter",
                        },
                        {
                            "skuId": "sku-1",
                            "skuName": "Google Workspace Business Starter",
                        },
                        {
                            "skuId": "sku-2",
                            "skuName": "Google Workspace Enterprise Plus",
                        },
                    ]
                }
            ]
        },
        "expected": {
            "license_data": [
                {
                    "product_name": "Google Workspace Business Starter",
                    "sku_id": "sku-1",
                    "product_id": "Google-Apps",
                    "status": "Active",
                    "assigned": 2,
                },
                {
                    "product_name": "Google Workspace Enterprise Plus",
                    "sku_id": "sku-2",
                    "product_id": "Google-Apps",
                    "status": "Active",
                    "assigned": 1,
                },
            ]
        },
        "expected_customer_id": "example.com",
        "expect_success_call": True,
        "expect_warning": False,
    },
    # Handles paginated license assignment responses.
    {
        "product_ids": ["Google-Apps"],
        "domains": [{"domainName": "example.com", "isPrimary": True}],
        "product_responses": {
            "Google-Apps": [
                {
                    "items": [
                        {
                            "skuId": "sku-1",
                            "skuName": "Google Workspace Business Starter",
                        }
                    ],
                    "nextPageToken": "page-2",
                },
                {
                    "items": [
                        {
                            "skuId": "sku-1",
                            "skuName": "Google Workspace Business Starter",
                        }
                    ]
                },
            ]
        },
        "expected": {
            "license_data": [
                {
                    "product_name": "Google Workspace Business Starter",
                    "sku_id": "sku-1",
                    "product_id": "Google-Apps",
                    "status": "Active",
                    "assigned": 2,
                }
            ]
        },
        "expected_customer_id": "example.com",
        "expect_success_call": True,
        "expect_warning": False,
    },
    # Successful API call with no assigned licenses.
    {
        "product_ids": ["Google-Apps"],
        "domains": [{"domainName": "example.com", "isPrimary": True}],
        "product_responses": {
            "Google-Apps": [{"items": []}]
        },
        "expected": {"license_data": []},
        "expected_customer_id": "example.com",
        "expect_success_call": True,
        "expect_warning": False,
    },
    # Falls back to the customer id when no primary domain is present.
    {
        "product_ids": ["Google-Apps"],
        "domains": [{"domainName": "alias.example.com", "isPrimary": False}],
        "product_responses": {
            "Google-Apps": [{"items": []}]
        },
        "expected": {"license_data": []},
        "expected_customer_id": "test_customer",
        "expect_success_call": True,
        "expect_warning": False,
    },
    # One product succeeds while another fails.
    {
        "product_ids": ["Google-Apps", "101047"],
        "domains": [{"domainName": "example.com", "isPrimary": True}],
        "product_responses": {
            "Google-Apps": "raises",
            "101047": [
                {
                    "items": [
                        {
                            "skuId": "gemini-sku",
                            "skuName": "Gemini Enterprise",
                        }
                    ]
                }
            ],
        },
        "expected": {
            "license_data": [
                {
                    "product_name": "Gemini Enterprise",
                    "sku_id": "gemini-sku",
                    "product_id": "101047",
                    "status": "Active",
                    "assigned": 1,
                }
            ]
        },
        "expected_customer_id": "example.com",
        "expect_success_call": True,
        "expect_warning": False,
    },
    # All product calls fail.
    {
        "product_ids": ["Google-Apps", "101047"],
        "domains": [{"domainName": "example.com", "isPrimary": True}],
        "product_responses": {
            "Google-Apps": "raises",
            "101047": "raises",
        },
        "expected": {"license_data": []},
        "expected_customer_id": "example.com",
        "expect_success_call": False,
        "expect_warning": False,
    },
    # Licensing service build fails.
    {
        "product_ids": ["Google-Apps"],
        "domains": [{"domainName": "example.com", "isPrimary": True}],
        "product_responses": {},
        "build_raises": Exception("licensing unavailable"),
        "expected": {"license_data": []},
        "expected_customer_id": "example.com",
        "expect_success_call": False,
        "expect_warning": True,
    },
]
