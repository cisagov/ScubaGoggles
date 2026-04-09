"""Tests for the GmailRulesParser class.
"""

from pathlib import Path

# The import is needed as stated and not how pylint wants it.
# pylint: disable=consider-using-from-import

import google.auth.transport.requests as requests
import scubagoggles.auth as auth

from scubagoggles.parsers.gmail_rules_parser import GmailRulesParser
from scubagoggles.policy_api import PolicyAPI
from scubagoggles.Testing.Unit.Python.test_policy_api import CommonMethods


class MockGwsAuth:

    """Mocks the GwsAuth class - the tests in this module do not call any
    Google API.
    """

    # pylint: disable=missing-function-docstring
    # pylint: disable=too-few-public-methods

    @property
    def credentials(self):
        return None

    def __init__(self, credentials_path, customer_id, services):
        self.credentials_path = credentials_path
        self.customer_id = customer_id
        self.services = services
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

auth.GwsAuth = MockGwsAuth

requests.AuthorizedSession = MockSession

# pylint: disable=too-few-public-methods


class TestGmailRulesParser:

    """This class contains unit tests for the GmailRulesParser class.

    Most of the gmail rules parser functionality is tested via the Policy
    API class unit tests.
    """

    # The test module needs to access "internal" methods.
    # pylint: disable=protected-access

    _common = CommonMethods(Path(__file__).parent / 'data')

    def test_gmail_address_lists(self, monkeypatch, subtests):

        """Tests the method for parsing Gmail address lists.
        """

        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('gmail_rules_addr'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch, test_data)
                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                policies = test_data['policies']
                gmail_parser = GmailRulesParser(policy_api, policies)
                assert gmail_parser._address_lists == test_data['results']
