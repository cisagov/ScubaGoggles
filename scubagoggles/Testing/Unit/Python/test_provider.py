"""
test_provider tests the Provider class.
"""

from scubagoggles.provider import Provider

class TestProvider:
    def _provider(self, mocker, **overrides) -> Provider:
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

        def build_side_effect(service_name, version, **kwargs):
            if service_name == "admin" and version == "directory_v1":
                return mock_directory
            return mock_service

        mocker.patch("scubagoggles.provider.build", side_effect=build_side_effect)

        defaults = {
            "customer_id": "test_customer",
            "credentials_file": "credentials.json",
            "access_token": "token",
            "svc_account_email": "svc@test.com",
        }
        params = {**defaults, **overrides}
        return Provider(**params)

    def test_exit(self, mocker):
        """
        Docstring for test_exit
        
        :param self: Description
        """
        provider = self._provider(mocker)

        for key in provider._services:
            mock_resource = mocker.Mock()
            provider._services[key] = mock_resource
        
        provider.__exit__(None, None, None)
        
        for resource in provider._services.values():
            resource.close.assert_called_once()

    def test_initialize_services(self):
        """
        Docstring for test_initialize_services
        
        :param self: Description
        """
        pass

    def test_list_domains(self):
        """
        Docstring for test_list_domains
        
        :param self: Description
        """
        pass

    def test_list_alias_domains(self):
        """
        Docstring for test_list_alias_domains
        
        :param self: Description
        """
        pass

    def test_get_spf_records(self):
        """
        Docstring for test_get_spf_records
        
        :param self: Description
        """
        pass

    def test_get_dkim_records(self):
        """
        Docstring for test_get_dkim_records
        
        :param self: Description
        """
        pass

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