"""
auth.py is the authentication module.

This module uses a local credential.json file to authenticate to a GWS org
"""

import json
from pathlib import Path

from google.auth.credentials import TokenState
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.oauth2.service_account import Credentials as SvcCredentials
from google_auth_oauthlib.flow import InstalledAppFlow

# The class is worth it just for the encapsulation.  It allows the potential
# of credential refresh multiple times, which may be beneficial during a
# prolonged debugging session.
# pylint: disable=too-few-public-methods


class GwsAuth:

    """Generates an Oauth token for accessing Google's APIs
    """

    _base_auth_url = 'https://www.googleapis.com/auth'

    _scopes = (f'{_base_auth_url}/admin.reports.audit.readonly',
               f'{_base_auth_url}/admin.directory.domain.readonly',
               f'{_base_auth_url}/admin.directory.orgunit.readonly',
               f'{_base_auth_url}/admin.directory.user.readonly',
               f'{_base_auth_url}/admin.directory.group.readonly',
               f'{_base_auth_url}/admin.directory.customer.readonly',
               f'{_base_auth_url}/apps.groups.settings',
               f'{_base_auth_url}/cloud-identity.policies.readonly')

    def __init__(self, credentials_path: Path, svc_account_email: str = None):
        """GwsAuth class initialization.

        The Google credentials are established when the class instance is
        created.  This may involve the user interacting with the web browser
        to authenticate for access to Google's API services.

        :param credentials_path: path to the Google JSON-format
            credentials file.
        :param svc_account_email: (optional) email address for the service
            account.
        """

        credentials_path = Path(credentials_path)

        if not credentials_path.exists():
            raise FileNotFoundError(f'{credentials_path} - credentials file '
                                    'not found')

        credentials_dir = credentials_path.parent
        self._credentials_path = credentials_path

        self._svc_account_email = svc_account_email
        if svc_account_email:
            get_credentials = SvcCredentials.from_service_account_file
            self._token = get_credentials(str(credentials_path),
                                          scopes=self._scopes,
                                          subject=svc_account_email)
            return

        # The token file is written to the same location as the given
        # credentials file.
        self._token_path = credentials_dir / 'token.json'
        self._load_token()
        if self._token:
            return

        # There is no existing token file, so the user will have to authenticate
        # using a browser on the current system.  There doesn't seem to be an
        # alternative for users without access to a browser (there was a
        # run_console() method that was removed in a prior release that may
        # have worked when no browser was available).
        credentials_file = str(self._credentials_path)
        flow = InstalledAppFlow.from_client_secrets_file(credentials_file,
                                                         self._scopes)

        try:
            self._token = flow.run_local_server(
                timeout_seconds=300, prompt='consent')
        except AttributeError as ae:
            raise RuntimeError('Google authorization timeout') from ae

        self._save_token()

    @property
    def credentials(self) -> Credentials:
        """Returns the Google credentials, after a possible refresh if needed.
        Token refresh doesn't apply to service accounts.

        :return: valid Google credentials
        """

        if not self._svc_account_email:
            self._refresh_token()

        return self._token

    def _check_scopes(self):
        """Compares the list of scopes in the token file with those defined
        in this class.  If there is a mismatch, the token file is deleted.
        It must be created if the scopes differ because operations that
        require the token may fail.
        """

        if not self._token_path.exists():
            return

        with self._token_path.open() as in_stream:
            token = json.load(in_stream)

        token_scopes = frozenset(token['scopes'])
        valid_scopes = frozenset(self._scopes)

        # Delete the token file if its scopes don't match those defined in
        # this class.  The token file will be recreated in the constructor
        # (with the user having to interact with the browser).
        if token_scopes != valid_scopes:
            self._token_path.unlink(missing_ok=True)

    def _load_token(self):
        """Loads and existing Google API token file, if it exists, and
        refreshes the token if necessary.

        This method is called during class instance initialization.  The
        "_token" attribute is defined for the instance, and is None if
        the token file doesn't exist.
        """

        self._token = None

        self._check_scopes()

        if not self._token_path.exists():
            return

        # The token file exists and its scopes match those defined in this
        # class.  Create credentials using the token file and scopes, and
        # refresh the token if it has expired.
        token_file = str(self._token_path)
        self._token = Credentials.from_authorized_user_file(token_file,
                                                            self._scopes)

        self._refresh_token()

    def _refresh_token(self):
        """Refreshes the credentials token if needed and writes the
        new credentials data to the token file.
        """

        if self._token.token_state != TokenState.FRESH:
            self._token.refresh(Request())
            self._save_token()

    def _save_token(self):
        """Writes the Google credentials to the token JSON file.
        """

        with self._token_path.open(mode='w', encoding='utf-8') as out:
            out.write(self._token.to_json())
