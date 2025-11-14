"""
test_policy_api tests the PolicyAPI class.
"""

import pytest
from scubagoggles.policy_api import PolicyAPI

@pytest.fixture
def gws_auth(mocker):
    mock_gws_auth = mocker.Mock()
    mock_gws_auth.credentials = mocker.Mock()
    return mock_gws_auth

@pytest.fixture
def policy_api(gws_auth, mocker):
    mock_session = mocker.Mock()
    # Patch the instance of AuthorizedSession already imported in policy_api,
    # not the version directly from google.auth.transport.requests.
    mocker.patch("scubagoggles.policy_api.AuthorizedSession", return_value=mock_session)
    mocker.patch.object(PolicyAPI, "_get_ou", return_value={
        "01abc23defgh456": {
            "name": "Root OU",
            "path": "/Root OU",
        },
        "02ijk45lmnop789": {
            "name": "Test OU 1",
            "path": "/Test OU 1",
        },
    })
    mocker.patch.object(PolicyAPI, "_get_groups", return_value={
        "01abc23defgh456": "Group A",
        "02ijk45lmnop789": "Group B",
    })
    return PolicyAPI(gws_auth, top_orgunit="Root OU")

class TestPolicyAPI:
    """Unit tests for the PolicyAPI class."""

    def test_close(self, policy_api, mocker):
        """Test the close method."""
        mock_session_close = mocker.patch.object(policy_api._session, "close")
        policy_api.close()
        mock_session_close.assert_called_once()
    
    @pytest.mark.parametrize(
        ("policies_list", "expected"),
        [
            # Single OU
            (
                [
                    {
                        "name": "policies/abc123",
                        "customer": "customers/C03ymv5su",
                        "policyQuery": {"orgUnit": "orgUnits/01abc23defgh456", "sortOrder": 1},
                        "setting": {"type": "settings/gmail_service_status", "value": {"serviceState": "enabled"}},
                        "type": "SYSTEM",
                    }
                ],
                {
                    "Root OU": {
                        "gmail_service_status": {
                            "serviceState": "enabled",
                        }
                    }
                }
            ),
            # Multiple OUs
            (
                [
                    {
                        "name": "policies/abc123",
                        "customer": "customers/C03ymv5su",
                        "policyQuery": {"orgUnit": "orgUnits/01abc23defgh456", "sortOrder": 1},
                        "setting": {"type": "settings/gmail_service_status", "value": {"serviceState": "enabled"}},
                        "type": "SYSTEM",
                    },
                    {
                        "name": "policies/def456",
                        "customer": "customers/C03ymv5su",
                        "policyQuery": {"orgUnit": "orgUnits/02ijk45lmnop789", "sortOrder": 1},
                        "setting": {"type": "settings/gmail_service_status", "value": {"serviceState": "disabled"}},
                        "type": "SYSTEM",
                    },
                    {
                        "name": "policies/ghi789",
                        "customer": "customers/C03ymv5su",
                        "policyQuery": {"orgUnit": "orgUnits/01abc23defgh456", "sortOrder": 1},
                        "setting": {"type": "settings/drive_and_docs_service_status", "value": {"serviceState": "enabled"}},
                        "type": "SYSTEM",
                    },
                ],
                {
                    "Root OU": {
                        "gmail_service_status": {
                            "serviceState": "enabled",
                        },
                        "drive_and_docs_service_status": {
                            "serviceState": "enabled",
                        },
                    },
                    "Test OU 1": {
                        "gmail_service_status": {
                            "serviceState": "disabled",
                        }
                    },
                },
            ),
            # No OUs
            (
                [],
                {},
            ),
        ]
    )
    def test_get_policies(
        self, 
        policy_api,
        mocker,
        policies_list,
        expected):
        """
        Tests PolicyAPI.get_policies() for these cases:
            - Single OU
            - Multiple OUs
            - No OUs
        """
        mocker.patch.object(policy_api, "_get_policies_list", return_value=policies_list)
        # Mock _apply_defaults since it'll be tested separately
        mocker.patch.object(policy_api, "_apply_defaults")

        result = policy_api.get_policies()
        assert result == expected
    
    @pytest.mark.parametrize(
        ("api_response, expected"),
        [
            # Two OUs
            (
                {
                    "organizationUnits": [
                        {"orgUnitId": "id:01abc23defgh456", "name": "Root OU", "orgUnitPath": "/Root OU"},
                        {"orgUnitId": "id:02ijk45lmnop789", "name": "Test OU 1", "orgUnitPath": "/Test OU 1"},
                    ]
                },
                {
                    "01abc23defgh456": {"name": "Root OU", "path": "/Root OU"},
                    "02ijk45lmnop789": {"name": "Test OU 1", "path": "/Test OU 1"},
                },
            ),
            # No OUs
            (
                {"organizationUnits": []},
                {},
            ),
            # Next page token error
            (
                {"organizationUnits": [], "nextPageToken": "abc"},
                pytest.raises(RuntimeError),
            ),
        ]
    )
    def test_get_ou(self, policy_api, mocker, api_response, expected):
        """
        Tests PolicyAPI._get_ou() for:
            - Typical response
            - Empty response
            - Next page token error
        """
        mocker.patch.object(policy_api, "_get", return_value=api_response)
        if isinstance(expected, type(pytest.raises(Exception))):
            with expected:
                policy_api._get_ou()
        else:
            result = policy_api._get_ou()
            assert result == expected
