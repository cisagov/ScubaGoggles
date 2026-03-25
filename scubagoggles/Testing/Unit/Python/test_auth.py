"""Unit tests for the auth.py module.

This module contains unit tests for the GwsAuth class,
following the ScubaGoggles testing framework patterns.
"""

import json
from pathlib import Path

import pytest

from google.auth.credentials import TokenState
from google.oauth2.credentials import Credentials
from google.oauth2.service_account import Credentials as SvcCredentials
from google_auth_oauthlib.flow import InstalledAppFlow

from scubagoggles.auth import GwsAuth
from scubagoggles.scuba_constants import API_SCOPES


class TestGwsAuth:

    """Test class for the GwsAuth authentication class.
    """

    @pytest.fixture
    def credentials_file(self, tmp_path):

        """Fixture providing a temporary credentials JSON file.
        """

        creds_path = tmp_path / 'credentials.json'
        creds_data = {
            "installed": {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        }
        creds_path.write_text(json.dumps(creds_data))
        return creds_path

    @pytest.fixture
    def token_file(self, tmp_path):

        """Fixture providing a token JSON file with matching scopes.

        Must be used alongside the credentials_file fixture so both
        reside in the same tmp_path directory.
        """

        token_path = tmp_path / 'token.json'
        token_data = {
            "token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "scopes": list(API_SCOPES),
            "client_id": "test_client_id",
            "client_secret": "test_client_secret"
        }
        token_path.write_text(json.dumps(token_data))
        return token_path

    @pytest.fixture
    def mock_fresh_credentials(self, mocker):

        """Fixture providing a mock Credentials object in FRESH state.
        """

        mock_creds = mocker.Mock(spec=Credentials)
        mock_creds.token_state = TokenState.FRESH
        mock_creds.to_json.return_value = json.dumps({
            "token": "test_token",
            "scopes": list(API_SCOPES)
        })
        return mock_creds

    def test_init_raises_file_not_found_error_for_missing_credentials(self):

        """Verify FileNotFoundError is raised when credentials file
        does not exist.
        """

        missing_path = Path('/nonexistent/path/credentials.json')

        with pytest.raises(FileNotFoundError,
                           match='credentials file not found'):
            GwsAuth(missing_path)

    def test_init_uses_service_account_credentials(self, mocker,
                                                   credentials_file):

        """Verify service account credentials are loaded when
        svc_account_email is provided.
        """

        mock_svc_creds = mocker.Mock(spec=SvcCredentials)
        mock_from_svc = mocker.patch.object(
            SvcCredentials, 'from_service_account_file',
            return_value=mock_svc_creds
        )

        svc_email = 'test@project.iam.gserviceaccount.com'
        auth = GwsAuth(credentials_file, svc_account_email=svc_email)

        mock_from_svc.assert_called_once_with(
            str(credentials_file),
            scopes=API_SCOPES,
            subject=svc_email
        )
        assert auth.credentials is mock_svc_creds

    def test_init_opens_oauth_flow_if_token_missing(self, mocker,
                                                    credentials_file,
                                                    mock_fresh_credentials):

        """Verify OAuth installed-app flow is triggered when no
        token file exists.
        """

        mock_flow = mocker.Mock()
        mock_flow.run_local_server.return_value = mock_fresh_credentials

        mocker.patch.object(
            InstalledAppFlow, 'from_client_secrets_file',
            return_value=mock_flow
        )

        auth = GwsAuth(credentials_file)

        InstalledAppFlow.from_client_secrets_file.assert_called_once_with(
            str(credentials_file), API_SCOPES
        )
        mock_flow.run_local_server.assert_called_once_with(
            timeout_seconds=300, prompt='consent'
        )
        assert auth.credentials is mock_fresh_credentials

    def test_init_loads_token_when_scopes_match(self, mocker,
                                                credentials_file,
                                                token_file,
                                                mock_fresh_credentials):

        """Verify token is loaded from an existing token file when its
        scopes match the expected API_SCOPES.
        """

        mocker.patch.object(
            Credentials, 'from_authorized_user_file',
            return_value=mock_fresh_credentials
        )

        auth = GwsAuth(credentials_file)

        Credentials.from_authorized_user_file.assert_called_once_with(
            str(token_file), API_SCOPES
        )
        assert auth.credentials is mock_fresh_credentials

    def test_init_deletes_token_and_triggers_oauth_when_scopes_mismatch(
        self, mocker, credentials_file, mock_fresh_credentials
    ):

        """Verify a token file with mismatched scopes is deleted and
        the OAuth flow is triggered to obtain new credentials.
        """

        token_path = credentials_file.parent / 'token.json'
        mismatched_token = {
            "token": "old_token",
            "refresh_token": "old_refresh",
            "scopes": ["https://www.googleapis.com/auth/some.other.scope"],
            "client_id": "test_client_id",
            "client_secret": "test_client_secret"
        }
        token_path.write_text(json.dumps(mismatched_token))

        mock_flow = mocker.Mock()
        mock_flow.run_local_server.return_value = mock_fresh_credentials
        mocker.patch.object(
            InstalledAppFlow, 'from_client_secrets_file',
            return_value=mock_flow
        )

        auth = GwsAuth(credentials_file)

        mock_flow.run_local_server.assert_called_once()
        assert auth.credentials is mock_fresh_credentials

    def test_credentials_refreshes_expired_token(self, mocker,
                                                 credentials_file,
                                                 _token_file,
                                                 mock_fresh_credentials):

        """Verify an expired/stale token is refreshed when the
        credentials property is accessed.
        """

        mocker.patch.object(
            Credentials, 'from_authorized_user_file',
            return_value=mock_fresh_credentials
        )
        mocker.patch('scubagoggles.auth.Request')

        auth = GwsAuth(credentials_file)

        # Simulate the token becoming stale after initialization
        mock_fresh_credentials.token_state = TokenState.STALE
        _ = auth.credentials

        mock_fresh_credentials.refresh.assert_called_once()

    def test_credentials_returns_valid_token(self, mocker,
                                             credentials_file,
                                             _token_file,
                                             mock_fresh_credentials):

        """Verify a valid (FRESH) token is returned without triggering
        a refresh.
        """

        mocker.patch.object(
            Credentials, 'from_authorized_user_file',
            return_value=mock_fresh_credentials
        )

        auth = GwsAuth(credentials_file)

        result = auth.credentials

        mock_fresh_credentials.refresh.assert_not_called()
        assert result is mock_fresh_credentials
