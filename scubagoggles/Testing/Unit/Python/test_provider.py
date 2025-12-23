"""
test_provider tests the Provider class.
"""
import pytest
from scubagoggles.provider import Provider, SELECTORS

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
        ("domains", "query_response", "expected_dkim_records"),
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
                "answer": [],
                "nxdomain": False,
                "log_entries": [] }
            )

        

    def test_get_dmarc_records(self):
        """
        Docstring for test_get_dmarc_records
        
        :param self: Description
        """
        pass

    def test_get_dnsinfo(self):
        """
        Docstring for test_get_dnsinfo
        
        :param self: Description
        """
        pass

    def test_get_super_admins(self):
        """
        Docstring for test_get_super_admins
        
        :param self: Description
        """
        pass

    def test_get_ous(self):
        """
        Docstring for test_get_ous
        
        :param self: Description
        """
        pass

    def test_get_toplevel_ou(self):
        """
        Docstring for test_get_toplevel_ou
        
        :param self: Description
        """
        pass

    def test_get_tenant_info(self):
        """
        Docstring for test_get_tenant_info
        
        :param self: Description
        """
        pass

    def test_get_gws_logs(self):
        """
        Docstring for test_get_gws_logs
        
        :param self: Description
        """
        pass

    def test_get_group_settings(self):
        """
        Docstring for test_get_group_settings
        
        :param self: Description
        """
        pass

    def test_call_gws_providers(self):
        """
        Docstring for test_call_gws_providers
        
        :param self: Description
        """
        pass

    def test_get_list(self):
        """
        Docstring for test_get_list
        
        :param self: Description
        """
        pass

    def test_check_scopes(self):
        """
        Docstring for test_check_scopes
        
        :param self: Description
        """
        pass