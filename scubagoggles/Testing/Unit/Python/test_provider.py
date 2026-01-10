"""
test_provider tests the Provider class.
"""
import pytest
from scubagoggles.provider import Provider, SELECTORS
from scubagoggles.scuba_constants import ApiReference
from google.auth.exceptions import RefreshError

class TestProvider:
    @pytest.fixture
    def mock_build(self, mocker):
        mock_service = mocker.Mock()
        mock_directory = mocker.Mock()
        mock_orgunits = mocker.Mock()
        mock_groups = mocker.Mock()

        mock_orgunits.__enter__ = lambda s: s
        mock_orgunits.__exit__ = lambda s, exc_type, exc_val, exc_tb: None
        mock_orgunits.list.return_value.execute.return_value = {
            "organizationUnits": [{
                "orgUnitPath": "/",
                "name": "Root OU",
            }]
        }
        mock_directory.orgunits.return_value = mock_orgunits
        mock_directory.groups.return_value = mock_groups

        def mock_side_effect(service_name, version, **kwargs):
            if service_name == "admin" and version == "directory_v1":
                return mock_directory
            return mock_service

        mocker.patch("scubagoggles.provider.build", side_effect=mock_side_effect)
        return mock_service, mock_directory

    def _provider(self, mocker, mock_build, **overrides) -> Provider:
        defaults = {
            "customer_id": "test_customer",
            "credentials_file": "credentials.json",
            "access_token": "token",
            "svc_account_email": "svc@test.com",
        }
        params = {**defaults, **overrides}
        return Provider(**params)

    def test_exit(self, mocker, mock_build):
        """
        Docstring for test_exit
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        for key in provider._services:
            mock_resource = mocker.Mock()
            provider._services[key] = mock_resource
        
        provider.__exit__(None, None, None)
        
        for resource in provider._services.values():
            resource.close.assert_called_once()

    def test_initialize_services(self, mocker, mock_build):
        """
        Docstring for test_initialize_services
        
        :param self: Description
        """
        # _initialize_services() is called in __init__,
        # calling the provider instance is sufficient for testing
        provider = self._provider(mocker, mock_build)

        assert set(provider._services.keys()) == {"reports", "directory", "groups"}

        mock_service, mock_directory = mock_build
        for key in ["reports", "groups"]:
            assert provider._services[key] is mock_service
        assert provider._services["directory"] is mock_directory

    @pytest.mark.parametrize(
        ("api_response", "expected_domains"),
        [
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
    )
    def test_list_domains(
        self,
        mocker,
        mock_build,
        api_response,
        expected_domains
    ):
        """
        Docstring for test_list_domains
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        directory = mocker.Mock()
        provider._services["directory"] = directory

        mock_domains = mocker.Mock()
        domains_ctx_manager = mocker.MagicMock()
        domains_ctx_manager.__enter__.return_value = mock_domains
        domains_ctx_manager.__exit__.return_value = False
        directory.domains.return_value = domains_ctx_manager
        mock_domains.list.return_value.execute.return_value = api_response

        result = provider.list_domains()
        assert result == expected_domains

    @pytest.mark.parametrize(
        ("api_response", "expected_aliases"),
        [
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
    )
    def test_list_alias_domains(
        self,
        mocker,
        mock_build,
        api_response,
        expected_aliases
    ):
        """
        Docstring for test_list_alias_domains
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        directory = mocker.Mock()
        provider._services["directory"] = directory

        mock_aliases = mocker.Mock()
        alias_ctx_manager = mocker.MagicMock()
        alias_ctx_manager.__enter__.return_value = mock_aliases
        alias_ctx_manager.__exit__.return_value = False
        directory.domainAliases.return_value = alias_ctx_manager
        mock_aliases.list.return_value.execute.return_value = api_response

        result = provider.list_alias_domains()
        assert result == expected_aliases

    @pytest.mark.parametrize(
        ("domains", "query_response", "expected_spf_records"),
        [
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
    )
    def test_get_spf_records(
        self,
        mocker,
        mock_build,
        domains,
        query_response,
        expected_spf_records
    ):
        """
        Docstring for test_get_spf_records
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        def query_side_effect(domain):
            return query_response[domain]
        mock_query = mocker.patch.object(
            provider._dns_client, "query", side_effect=query_side_effect
        )

        result = provider.get_spf_records(domains)
        sorted_result = sorted(result, key=lambda x: x["domain"])
        sorted_expected = sorted(expected_spf_records, key=lambda x: x["domain"])
        assert sorted_result == sorted_expected
        assert mock_query.call_count == len(domains)

    @pytest.mark.parametrize(
        ("domains", "query_responses", "expected_dkim_records"),
        [
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
        ],
    )
    def test_get_dkim_records(
        self,
        mocker,
        mock_build,
        domains,
        query_responses,
        expected_dkim_records
    ):
        """
        Docstring for test_get_dkim_records
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        def query_side_effect(qname):
            return query_responses.get(qname, {
                "answers": [],
                "nxdomain": False,
                "log_entries": []
            })

        mock_query = mocker.patch.object(
            provider._dns_client,
            "query",
            side_effect=query_side_effect
        )

        result = provider.get_dkim_records(domains)
        result_map = {
            item["domain"]: {
                "rdata": item["rdata"],
                "log": item["log"]
            }
            for item in result
        }

        for expected in expected_dkim_records:
            domain = expected["domain"]
            assert domain in result_map
            assert result_map[domain]["rdata"] == expected["rdata"]
            
            result_log = result_map[domain]["log"]
            for expected_log in expected.get("log", []):
                assert expected_log in result_log, \
                f"Log entry {expected_log} not found for domain {domain}: {expected_log}"

        assert mock_query.call_count >= len(domains)

    @pytest.mark.parametrize(
        ("domains", "query_responses", "expected_dmarc_records"),
        [
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
    )
    def test_get_dmarc_records(
        self,
        mocker,
        mock_build,
        domains,
        query_responses,
        expected_dmarc_records
    ):
        """
        Docstring for test_get_dmarc_records
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        def query_side_effect(qname):
            return query_responses.get(qname, {
                "answers": [],
                "nxdomain": False,
                "log_entries": []
            })
        
        mock_query = mocker.patch.object(
            provider._dns_client,
            "query",
            side_effect=query_side_effect
        )

        result = provider.get_dmarc_records(domains)

        sorted_result = sorted(result, key=lambda x: x["domain"])
        sorted_expected = sorted(expected_dmarc_records, key=lambda x: x["domain"])
        assert sorted_result == sorted_expected
        assert mock_query.call_count >= len(domains)

    @pytest.mark.parametrize(
        "cases",
        [
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
        ],
    )
    def test_get_dnsinfo(self, mocker, mock_build, cases):
        """
        Verify if get_dnsinfo() collects verified base and alias domains,
        calls the respective methods (get_spf_records, get_dkim_records, etc.),
        then returns aggregated results in the expected key format.
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        base_domains = cases["base_domains"]
        alias_domains = cases["alias_domains"]
        spf_output = cases["spf_output"]
        dkim_output = cases["dkim_output"]
        dmarc_output = cases["dmarc_output"]
        expected_calls = cases["expected_calls"]

        mocker.patch.object(provider, "list_domains", return_value=base_domains)
        mocker.patch.object(provider, "list_alias_domains", return_value=alias_domains)

        spf_mock = mocker.patch.object(provider, "get_spf_records", return_value=spf_output)
        spf_mock.__name__ = "get_spf_records"
        dkim_mock = mocker.patch.object(provider, "get_dkim_records", return_value=dkim_output)
        dkim_mock.__name__ = "get_dkim_records"
        dmarc_mock = mocker.patch.object(provider, "get_dmarc_records", return_value=dmarc_output)
        dmarc_mock.__name__ = "get_dmarc_records"

        result = provider.get_dnsinfo()

        if expected_calls:
            assert result["domains"] == ["example.com"]
            assert result["alias_domains"] == ["alias.com"]
            assert result["spf_records"] == spf_output
            assert result["dkim_records"] == dkim_output
            assert result["dmarc_records"] == dmarc_output

            # Verify DNS methods are added to successful calls
            assert "get_spf_records" in provider._successful_calls
            assert "get_dkim_records" in provider._successful_calls
            assert "get_dmarc_records" in provider._successful_calls
        else:
            assert result["domains"] == []
            assert result["alias_domains"] == []
            assert result["spf_records"] == []
            assert result["dkim_records"] == []
            assert result["dmarc_records"] == []

            spf_mock.assert_not_called()
            dkim_mock.assert_not_called()
            dmarc_mock.assert_not_called()

    @pytest.mark.parametrize(
        "cases",
        [
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
        ]
    )
    def test_get_super_admins(
        self,
        mocker,
        mock_build,
        cases
    ):
        """
        Docstring for test_get_super_admins
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        users_resource = mocker.Mock(name="users_resource")
        users_ctx_manager = mocker.MagicMock(name="users_ctx_manager")
        users_ctx_manager.__enter__.return_value = users_resource
        users_ctx_manager.__exit__.return_value = False

        # users() context manager returns users resource passed into _get_list
        provider._services["directory"].users.return_value = users_ctx_manager

        # Patch _get_list for API success/fail cases
        get_list_mock = mocker.patch.object(Provider, "_get_list", autospec=True)
        if cases["get_list_raises"]:
            get_list_mock.side_effect = cases["get_list_raises"]
        else:
            get_list_mock.return_value = cases["user_list"]

        result = provider.get_super_admins()
        assert result == cases["expected"]

        if cases["expect_success_call"]:
            assert ApiReference.LIST_USERS.value in provider._successful_calls
            assert ApiReference.LIST_USERS.value not in provider._unsuccessful_calls

            get_list_mock.assert_called_once()
            resource_arg, item_arg = get_list_mock.call_args.args[:2]
            assert resource_arg is users_resource
            assert item_arg == "users"
            # "test_customer" is the default customer specified in _provider() above 
            assert get_list_mock.call_args.kwargs["customer"] == "test_customer"
            assert get_list_mock.call_args.kwargs["query"] == "isAdmin=True"
        else:
            assert ApiReference.LIST_USERS.value not in provider._successful_calls
            assert ApiReference.LIST_USERS.value in provider._unsuccessful_calls

    @pytest.mark.parametrize(
        "cases",
        [
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
    )
    def test_get_ous(self, mocker, mock_build, cases):
        """
        Docstring for test_get_ous
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        # Clear calls since get_toplevel_ou is called during provider initialization.
        # get_toplevel_ou calls the same ApiReference.LIST_OUS, so it'll be listed
        # under successful_calls prior to get_ous() being called.
        provider._successful_calls.clear()
        provider._unsuccessful_calls.clear()

        orgunits_resource = mocker.Mock(name="orgunits_resource")
        orgunits_ctx_manager = mocker.MagicMock(name="orgunits_ctx_manager")
        orgunits_ctx_manager.__enter__.return_value = orgunits_resource
        orgunits_ctx_manager.__exit__.return_value = False

        provider._services["directory"].orgunits.return_value = orgunits_ctx_manager

        if cases["raises"] is not None:
            orgunits_resource.list.return_value.execute.side_effect = cases["raises"]

            with pytest.warns(RuntimeWarning, match="Exception thrown while getting top level OU"):
                result = provider.get_ous()
        else:
            orgunits_resource.list.return_value.execute.return_value = cases["api_response"]
            result = provider.get_ous()
        
        assert result == cases["expected"]

        if cases["expect_success_call"]:
            assert ApiReference.LIST_OUS.value in provider._successful_calls
            assert ApiReference.LIST_OUS.value not in provider._unsuccessful_calls

            # If successful, verify API was called with correct parameters
            orgunits_resource.list.assert_called_once_with(customerId="test_customer")
        else:
            assert ApiReference.LIST_OUS.value not in provider._successful_calls
            assert ApiReference.LIST_OUS.value in provider._unsuccessful_calls

    @pytest.mark.parametrize(
            "cases",
            [
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
            ],
    )
    def test_get_toplevel_ou(self, mocker, mock_build, cases):
        """
        Docstring for test_get_toplevel_ou
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        provider._successful_calls.clear()
        provider._unsuccessful_calls.clear()

        orgunits_resource = mocker.Mock(name="orgunits_resource")
        orgunits_ctx_manager = mocker.MagicMock(name="orgunits_ctx_manager")
        orgunits_ctx_manager.__enter__.return_value = orgunits_resource
        orgunits_ctx_manager.__exit__.return_value = False
        provider._services["directory"].orgunits.return_value = orgunits_ctx_manager

        if cases["raises"] is not None:
            orgunits_resource.list.return_value.execute.side_effect = cases["raises"]

            if isinstance(cases["raises"], RefreshError):
                with pytest.raises(RefreshError, match="access_denied: Requested client not authorized"):
                    provider.get_toplevel_ou()
            else:
                with pytest.warns(RuntimeWarning, match="Exception thrown while getting top level OU"):
                    with pytest.raises(Exception, match="API error"):
                        provider.get_toplevel_ou()
            
            # No return value for exception cases, set to the default expected value
            result = cases["expected"]
        else:
            orgunits_resource.list.return_value.execute.return_value = cases["api_response"]
            result = provider.get_toplevel_ou()
        
        assert result == cases["expected"]

        if cases["expect_success_call"]:
            assert ApiReference.LIST_OUS.value in provider._successful_calls
            assert ApiReference.LIST_OUS.value not in provider._unsuccessful_calls

            orgunits_resource.list.assert_called_once_with(
                customerId="test_customer",
                orgUnitPath="/",
                type="allIncludingParent"
            )
        else:
            assert ApiReference.LIST_OUS.value not in provider._successful_calls
            # get_toplevel_ou re-raises the exception in _check_scopes(exc),
            # so _unsuccessful_calls may not be recorded.

    @pytest.mark.parametrize(
        "cases",
        [
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
                "customer_side_effect": RefreshError("access_denied: Requested client not authorized"),
                "domains": [ { "domainName": "example.com", "isPrimary": True }],
                "expected": {
                    "ID": "",
                    "domain": "Error Retrieving",
                    "topLevelOU": "Root OU",
                },
                "expect_warning": True,
            },
        ]
    )
    def test_get_tenant_info(self, mocker, mock_build, cases):
        """
        Docstring for test_get_tenant_info
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        provider._successful_calls.clear()
        provider._unsuccessful_calls.clear()
        provider._top_ou = "Root OU"

        customers_resource = mocker.Mock(name="customers_resource")
        provider._services["directory"].customers.return_value = customers_resource
        get_request = mocker.Mock(name="customers_get_request")
        customers_resource.get.return_value = get_request

        if cases["customer_side_effect"] is not None:
            get_request.execute.side_effect = cases["customer_side_effect"]
        else:
            get_request.execute.return_value = cases["customer_execute"]
        
        # We're not testing list_domains, mock with parametrized value
        mocker.patch.object(provider, "list_domains", return_value=cases["domains"])

        if cases["expect_warning"]:
            with pytest.warns(RuntimeWarning, match="Exception thrown while retrieving customer list"):
                with pytest.raises(UnboundLocalError):
                    provider.get_tenant_info()
            
            assert ApiReference.LIST_CUSTOMERS.value in provider._unsuccessful_calls
        else:
            result = provider.get_tenant_info()
            assert result == cases["expected"]
            assert ApiReference.LIST_CUSTOMERS.value not in provider._unsuccessful_calls

        customers_resource.get.assert_called_once_with(customerKey="test_customer")
        get_request.execute.assert_called_once()
    
    @pytest.mark.parametrize(
        "cases",
        [
            # Non-matching event
            {
                "products": ["gmail", "drive"],
                "event": "SOME_OTHER_EVENT",
                "reports": [
                    { "id": "meet", "events": [] },
                    { "id": "classroom", "events": [] },
                ],
                "expected": {
                    "gmail": [
                        { "id": "meet", "events": [] },
                        { "id": "classroom", "events": [] },
                    ],
                    "drive": [
                        { "id": "meet", "events": [] },
                        { "id": "classroom", "events": [] },
                    ],
                },
                "expect_warning": False,
            },
            # CHANGE_APPLICATION_SETTING with matching apps
            {
                "products": ["gmail", "drive"],
                "event": "CHANGE_APPLICATION_SETTING",
                "reports": [
                    {
                        "id": "gmail",
                        "events": [
                            {
                                "parameters": [
                                    { "name": "APPLICATION_NAME", "value": "Gmail"},
                                ]
                            }
                        ]
                    },
                    {
                        "id": "drive",
                        "events": [
                            {
                                "parameters": [
                                    { "name": "APPLICATION_NAME", "value": "Drive and Docs"},
                                ]
                            }
                        ]
                    },
                    {
                        "id": "no_match",
                        "events": [
                            {
                                "parameters": [
                                    { "name": "APPLICATION_NAME", "value": "Calendar"},
                                ]
                            }
                        ]
                    }
                ],
                "expected": {
                    "gmail": [
                        {
                            "id": "gmail",
                            "events": [
                                {
                                    "parameters": [
                                        { "name": "APPLICATION_NAME", "value": "Gmail"},
                                    ]
                                }
                            ]
                        }
                    ],
                    "drive": [
                        {
                            "id": "drive",
                            "events": [
                                {
                                    "parameters": [
                                        { "name": "APPLICATION_NAME", "value": "Drive and Docs"},
                                    ]
                                }
                            ]
                        }
                    ],
                },
                "expect_warning": False,
            },
            # DELETE_APPLICATION_SETTING with only marketplace app
            {
                "products": ["commoncontrols", "gmail"],
                "event": "DELETE_APPLICATION_SETTING",
                "reports": [
                    {
                        "id": "marketplace",
                        "events": [
                            {
                                "parameters": [
                                    { "name": "APPLICATION_NAME", "value": "Google Workspace Marketplace"},
                                ]
                            }
                        ]
                    }
                ],
                "expected": {
                    "gmail": [],
                    "commoncontrols": [
                        {
                            "id": "marketplace",
                            "events": [
                                {
                                    "parameters": [
                                        { "name": "APPLICATION_NAME", "value": "Google Workspace Marketplace"},
                                    ],
                                },
                            ],
                        },
                    ],
                },
                "expect_warning": False,
            },
            # Exception thrown when trying to retrieve logs
            {
                "products": ["gmail", "drive"],
                "event": "CHANGE_APPLICATION_SETTING",
                "reports": [{}],
                "expected": {
                    "gmail": [],
                    "drive": [],
                },
                "expect_warning": True,
            },
        ]
    )
    def test_get_gws_logs(self, mocker, mock_build, cases):
        """
        Docstring for test_get_gws_logs
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        activities_resource = mocker.Mock(name="activities_resource")
        activities_ctx_manager = mocker.MagicMock(name="activities_ctx_manager")
        activities_ctx_manager.__enter__.return_value = activities_resource
        activities_ctx_manager.__exit__.return_value = False
        provider._services["reports"].activities.return_value = activities_ctx_manager

        get_list = mocker.patch.object(Provider, "_get_list", return_value=cases["reports"])

        if cases["expect_warning"]:
            with pytest.warns(RuntimeWarning, match="An exception was thrown while getting the logs"):
                result = provider.get_gws_logs(products=cases["products"], event=cases["event"])
        else:
            result = provider.get_gws_logs(products=cases["products"], event=cases["event"])

        assert result == cases["expected"]

        get_list.assert_called_once_with(
            activities_resource,
            "items",
            userKey="all",
            applicationName="admin",
            eventName=cases["event"]
        )

    @pytest.mark.parametrize(
        "cases",
        [
            # Multiple groups returned
            (
                {
                    "groups_list_return": [
                        { "email": "user1.example.com" },
                        { "email": "user2.example.com" },
                    ],
                    "directory_side_effect": None,
                    "groups_side_effect": None,
                    "groups_expected": [
                        {
                            "kind": "groupsSettings#groups",
                            "email": "g1@scubagws.org",
                            "name": "Group 1",
                            "whoCanJoin": "INVITED_CAN_JOIN",
                        },
                        {
                            "kind": "groupsSettings#groups",
                            "email": "g2@scubagws.org",
                            "name": "Group 2",
                            "whoCanJoin": "INVITED_CAN_JOIN",
                        },
                    ]
                }
            ),
            # No groups returned
            (
                {
                    "groups_list_return": [],
                    "directory_side_effect": None,
                    "groups_side_effect": None,
                    "groups_expected": []
                }
            ),
            # Exception thrown when retrieving groups from Directory API
            (
                {
                    "groups_list_return": None,
                    "directory_side_effect": Exception("API error"),
                    "groups_side_effect": None,
                    "groups_expected": []
                }
            ),
            # Exception thrown when retrieving group settings from Groups Settings API
            (
                {
                    "groups_list_return": [
                        { "email": "user1.example.com" },
                    ],
                    "directory_side_effect": None,
                    "groups_side_effect": Exception("API error"),
                    "groups_expected": []
                }
            ),
        ],
    )
    def test_get_group_settings(self, mocker, mock_build, cases):
        """
        Docstring for test_get_group_settings
        
        :param self: Description
        """
        provider = self._provider(mocker, mock_build)

        directory_service = provider._services["directory"]
        groups_service = provider._services["groups"]

        ds_groups_resource = mocker.Mock(name="ds_groups_resource")
        ds_ctx_manager = mocker.MagicMock(name="ds_ctx_manager")
        ds_ctx_manager.__enter__.return_value = ds_groups_resource
        ds_ctx_manager.__exit__.return_value = False
        directory_service.groups.return_value = ds_ctx_manager

        gs_groups_resource = mocker.Mock(name="gs_groups_resource")
        gs_ctx_manager = mocker.MagicMock(name="gs_ctx_manager")
        gs_ctx_manager.__enter__.return_value = gs_groups_resource
        gs_ctx_manager.__exit__.return_value = False
        groups_service.groups.return_value = gs_ctx_manager

        get_list_mock = mocker.patch.object(Provider, "_get_list")
        get_list_mock.side_effect = cases["directory_side_effect"] or None
        get_list_mock.return_value = cases["groups_list_return"]

        gs_get_request = mocker.Mock(name="gs_get_request")
        if cases["groups_side_effect"] is not None:
            gs_get_request.execute.side_effect = cases["groups_side_effect"]
        else:
            gs_get_request.execute.side_effect = cases["groups_expected"]
        
        gs_groups_resource.get.return_value = gs_get_request

        warning_expected = (cases["directory_side_effect"] is not None or
                            cases["groups_side_effect"] is not None)
        
        if warning_expected:
            with pytest.warns(
                RuntimeWarning,
                match="Exception thrown while getting group settings; outputs will be incorrect"
            ):
                result = provider.get_group_settings()
            
            assert result == { "group_settings": [] }
            assert ApiReference.LIST_GROUPS.value not in provider._successful_calls
            assert ApiReference.GET_GROUP.value not in provider._successful_calls
            assert ApiReference.LIST_GROUPS.value in provider._unsuccessful_calls
            assert ApiReference.GET_GROUP.value in provider._unsuccessful_calls
        else:
            result = provider.get_group_settings()
            assert result == { "group_settings": cases["groups_expected"] }
            assert ApiReference.LIST_GROUPS.value in provider._successful_calls
            assert ApiReference.GET_GROUP.value in provider._successful_calls
            assert ApiReference.LIST_GROUPS.value not in provider._unsuccessful_calls
            assert ApiReference.GET_GROUP.value not in provider._unsuccessful_calls

            assert gs_groups_resource.get.call_count == len(cases["groups_list_return"])
            for group in cases["groups_list_return"]:
                gs_groups_resource.get.assert_any_call(groupUniqueId=group["email"])
            assert gs_get_request.execute.call_count == len(cases["groups_list_return"])

        get_list_mock.assert_called_once_with(
            ds_groups_resource,
            "groups",
            customer="test_customer"
        )

    @pytest.mark.parametrize(
        "cases",
        [
            (
                {
                    "products": ["gmail"],
                    "scenario": None,
                }
            ),
            (
                {
                    "products": ["commoncontrols", "groups"],
                    "scenario": None,
                }
            ),
            (
                {
                    "products": ["gmail"],
                    "scenario": "tenant_data",
                }
            ),
            (
                {
                    "products": ["gmail"],
                    "scenario": "logs",
                }
            ),
            (
                {
                    "products": ["gmail"],

                }
            ),
        ],
    )
    def test_call_gws_providers(self):
        """
        Docstring for test_call_gws_providers
        
        :param self: Description
        """
        pass

    def test_check_scopes(self):
        """
        Docstring for test_check_scopes
        
        :param self: Description
        """
        pass