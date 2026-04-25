"""Common fixtures for unit tests.
"""

from functools import partial
from unittest.mock import MagicMock, PropertyMock

import pytest

from scubagoggles.auth import GwsAuth
from scubagoggles.policy_api import PolicyAPI

@pytest.fixture
def mock_policy_api(monkeypatch):

    """Returns a mock of the Policy API class that may be instantiated without
    the GwsAuth instance parameter.  This mocks both the GwsAuth and Google's
    AuthorizedSession classes.  It removes the authentication and calls to
    Google's APIs so that other areas of the PolicyAPI class can be mocked for
    testing.

    :return: PolicyAPI class that can be initialized with only the top-level
        orgunit parameter.
    """

    class MockSession:

        """Mocks Google's AuthorizedSession class.  This along with the above
        class are used to allow the instantiation of the PolicyAPI class without
        making any calls to the Google API.
        """

        # pylint: disable=missing-function-docstring

        def __init__(self, credentials):
            self._close_count = 0
            self._credentials = credentials

        def close(self):
            self._close_count += 1

        def get(self, *_):
            pass

    mock_gws_auth = MagicMock(spec = GwsAuth)

    type(mock_gws_auth).credentials = PropertyMock(return_value = None)

    session_module = 'google.auth.transport.requests.AuthorizedSession'

    monkeypatch.setattr(session_module, MockSession)

    return partial(PolicyAPI, mock_gws_auth)
