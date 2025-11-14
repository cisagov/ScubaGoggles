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
