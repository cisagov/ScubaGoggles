"""
test_provider tests the Provider class.
"""
import pytest
from google.auth.exceptions import RefreshError
from scubagoggles.provider import Provider
from scubagoggles.scuba_constants import ApiReference

from scubagoggles.Testing.Unit.Python.provider.domain_cases import (
    LIST_DOMAINS_CASES,
    LIST_ALIAS_DOMAINS_CASES,
)
from scubagoggles.Testing.Unit.Python.provider.dns_cases import (
    GET_SPF_RECORDS_CASES,
    GET_DKIM_RECORDS_CASES,
    GET_DMARC_RECORDS_CASES,
    GET_DNSINFO_CASES,
)
from scubagoggles.Testing.Unit.Python.provider.admin_ou_cases import (
    GET_SUPER_ADMIN_CASES,
    GET_OU_CASES,
    GET_TOPLEVEL_OU_CASES,
    GET_TENANT_INFO_CASES,
)
from scubagoggles.Testing.Unit.Python.provider.log_cases import (
    GET_GWS_LOGS_CASES,
)
from scubagoggles.Testing.Unit.Python.provider.group_cases import (
    GET_GROUP_SETTINGS_CASES,
)

# Disable "protected-access" because we test some internal methods;
# Disable "too-many-positional-arguments" because some tests have
# 6 vs the expected 5 parameter limit, don't need to refactor this.
# pylint: disable=protected-access,too-many-positional-arguments

class TestProvider:
    """Unit tests for the Provider class."""

    @pytest.fixture
    def mock_build(self, mocker):
        """
        Fixture that patches the googleapiclient.discovery build()
        method so no Google API clients are created during tests.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        """
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

        def mock_side_effect(service_name, version, **_kwargs):
            if service_name == "admin" and version == "directory_v1":
                return mock_directory
            return mock_service

        mocker.patch("scubagoggles.provider.build", side_effect=mock_side_effect)
        return mock_service, mock_directory

    def _provider(self, _mocker, _mock_build, **overrides) -> Provider:
        """
        Helper method that constructs a Provider instance with default parameters,
        overrides can be specified if preferred.

        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param **overrides: Overrides for the Provider parameters.
        """
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
        Verifies Provider.__exit__ closes all service resources.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
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
        Verifies Provider initialization creates services for reports,
        directory, and groups.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
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
        LIST_DOMAINS_CASES
    )
    def test_list_domains(
        self,
        mocker,
        mock_build,
        api_response,
        expected_domains
    ):
        """
        Verifies Provider.list_domains() returns the `domains` list 
        from the Directory API.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param api_response: Parametrized object representing the API response.
        :param expected_domains: Parametrized list representing the expected domains.
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
        LIST_ALIAS_DOMAINS_CASES
    )
    def test_list_alias_domains(
        self,
        mocker,
        mock_build,
        api_response,
        expected_aliases
    ):
        """
        Verifies Provider.list_alias_domains() returns the `domainAliases` list
        from the Directory API.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param api_response: Parametrized object representing the API response.
        :param expected_aliases: Parametrized list representing the expected domain aliases.
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
        GET_SPF_RECORDS_CASES
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
        Verifies Provider.get_spf_records() queries/returns the expected
        TXT records for each domain; returns expected output with `domain`, 
        `rdata`, and `log` keys.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param domains: Parametrized set of domains to query for SPF records.
        :param query_response: Parametrized mapping of domain to query response.
        :param expected_spf_records: Parametrized list representing the SPF results.
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
        GET_DKIM_RECORDS_CASES
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
        Verifies Provider.get_dkim_records() queries DKIM TXT records
        using the configured selectors and returns expected output.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param domains: Parametrized set of domains to query for DKIM records.
        :param query_responses: Parametrized mapping of domain to query response.
        :param expected_dkim_records: Parametrized list representing the DKIM results.
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
        GET_DMARC_RECORDS_CASES
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
        Verifies Provider.get_dmarc_records() queries DMARC TXT records
        at "_dmarc.<domain>" and returns expected results.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param domains: Parametrized set of domains/subdomains to query for DMARC records.
        :param query_responses: Parametrized mapping of query name, e.g. "_dmarc.example.com", 
        to the DNS client response object that contains `answers`, `nxdomain`, and `log_entries`. 
        :param expected_dmarc_records: Parametrized list representing the DMARC results.
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
        GET_DNSINFO_CASES
    )
    def test_get_dnsinfo(self, mocker, mock_build, cases):
        """
        Verify if get_dnsinfo() collects verified base and alias domains,
        calls the respective methods (get_spf_records, get_dkim_records, etc.),
        then returns aggregated results in the expected key format. The test cases
        defined here confirm if the correct domains/alias domains are returned,
        returns the expected object format for domains/alias domains, spf_records,
        dkim_records, and dmarc_records.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing domain and DNS record information.
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
            assert not result["domains"]
            assert not result["alias_domains"]
            assert not result["spf_records"]
            assert not result["dkim_records"]
            assert not result["dmarc_records"]

            spf_mock.assert_not_called()
            dkim_mock.assert_not_called()
            dmarc_mock.assert_not_called()

    @pytest.mark.parametrize(
        "cases",
        GET_SUPER_ADMIN_CASES
    )
    def test_get_super_admins(
        self,
        mocker,
        mock_build,
        cases
    ):
        """
        Verify if Provider.get_super_admins() retrieves admin users
        from the Directory API.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing user list and expected results.
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
        GET_OU_CASES
    )
    def test_get_ous(self, mocker, mock_build, cases):
        """
        Verifies Provider.get_ous() gets OUs from the Directory API
        and returns the raw OU list. These tests cover successful API response
        with multiple OUs, no OUs, API exceptions, and correct
        successful/unsuccessful ApiReference calls.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing metadata for OU response/exceptions.
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
            orgunits_resource.list.assert_called_once_with(
                customerId="test_customer",
                type="allIncludingParent"
            )
        else:
            assert ApiReference.LIST_OUS.value not in provider._successful_calls
            assert ApiReference.LIST_OUS.value in provider._unsuccessful_calls

    @pytest.mark.parametrize(
            "cases",
            GET_TOPLEVEL_OU_CASES
    )
    def test_get_toplevel_ou(self, mocker, mock_build, cases):
        """
        Verifies if Provider.get_toplevel_ou() gets the tenant's 
        root OU. These test cases the presence of a root OU, absence of a root OU,
        exception handling for warning/raise, and RefreshError exceptions
        if access to the requested API is denied.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing metadata for OU response/exceptions.
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
                with pytest.raises(
                    RefreshError,
                    match="access_denied: Requested client not authorized"
                ):
                    provider.get_toplevel_ou()
            else:
                with pytest.warns(
                    RuntimeWarning,
                    match="Exception thrown while getting top level OU"
                ):
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
        GET_TENANT_INFO_CASES
    )
    def test_get_tenant_info(self, mocker, mock_build, cases):
        """
        Verifies if Provider.get_tenant_info() gets the tenant/customer
        metadata. These test cases cover successful calls to customers.get().execute(), 
        handling cases where a primary domain is missing, exception handling,
        and correct successful/unsuccessful ApiReference calls.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing metadata
                      for tenant info response/exceptions.
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
            with pytest.warns(
                RuntimeWarning,
                match="Exception thrown while retrieving customer list"
            ):
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
        GET_GWS_LOGS_CASES
    )
    def test_get_gws_logs(self, mocker, mock_build, cases):
        """
        Verifies if Provider.get_gws_logs() retrieves Admin logs and
        filters them by the requested product/event type. These test 
        cases cover calls to Provider._get_list() for reports.activities().list
        results, filtering on different events, and exception handling.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing metadata for GWS logs response/exceptions.
        """
        provider = self._provider(mocker, mock_build)

        activities_resource = mocker.Mock(name="activities_resource")
        activities_ctx_manager = mocker.MagicMock(name="activities_ctx_manager")
        activities_ctx_manager.__enter__.return_value = activities_resource
        activities_ctx_manager.__exit__.return_value = False
        provider._services["reports"].activities.return_value = activities_ctx_manager

        get_list = mocker.patch.object(Provider, "_get_list", return_value=cases["reports"])

        if cases["expect_warning"]:
            with pytest.warns(
                RuntimeWarning,
                match="An exception was thrown while getting the logs"
            ):
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
        GET_GROUP_SETTINGS_CASES
    )
    def test_get_group_settings(self, mocker, mock_build, cases):
        """
        Verifies Provider.get_group_settings() lists groups from the Directory
        API and then gets group settings from the Groups Settings API. 
        These test cases cover successful listing of groups, successful retrieval of 
        each group's settings, Directory API exceptions, Groups Settings API 
        exceptions, and correct successful/unsuccessful ApiReference calls.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        :param cases: Parametrized test cases containing metadata for OU response/exceptions.
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

    def test_check_scopes(self, mocker, mock_build):
        """
        Verifies if Provider._check_scopes() handles auth-related
        exceptions.
        
        :param mocker: pytest-mock fixture used to create mocks/patch functions.
        :param mock_build: Fixture that patches the googleapiclient.discovery build() method.
        """
        provider = self._provider(mocker, mock_build)

        provider._credentials = mocker.Mock()
        provider._credentials.scopes = ["scopeA", "scopeB"]

        log_error = mocker.patch("scubagoggles.provider.log.error")

        denied_exc = Exception("access_denied: Requested client not authorized.")
        with pytest.raises(Exception) as excinfo:
            provider._check_scopes(denied_exc)

        assert excinfo.value is denied_exc
        log_error.assert_called_once_with(
            "Your credential may be missing one of the following scopes: %s",
            ["scopeA", "scopeB"],
        )

        log_error.reset_mock()
        other_exc = Exception("some other error")
        with pytest.raises(Exception) as excinfo:
            provider._check_scopes(other_exc)

        assert excinfo.value is other_exc
        log_error.assert_not_called()
