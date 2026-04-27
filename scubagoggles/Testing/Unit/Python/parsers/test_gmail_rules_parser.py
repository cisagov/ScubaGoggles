"""Tests for the GmailRulesParser class.
"""

from pathlib import Path

from scubagoggles.parsers.gmail_rules_parser import GmailRulesParser
from scubagoggles.Testing.Unit.Python.test_policy_api import CommonMethods

# pylint: disable=too-few-public-methods


class TestGmailRulesParser:

    """This class contains unit tests for the GmailRulesParser class.

    Most of the gmail rules parser functionality is tested via the Policy
    API class unit tests.
    """

    # The test module needs to access "internal" methods.
    # pylint: disable=protected-access

    _common = CommonMethods(Path(__file__).parent / 'data')

    def test_gmail_address_lists(self, monkeypatch, subtests, mock_policy_api):

        """Tests the method for parsing Gmail address lists.
        """

        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('gmail_rules_addr'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch, test_data)
                policy_api = mock_policy_api('topOU')
                policies = test_data['policies']
                gmail_parser = GmailRulesParser(policy_api, policies)
                assert gmail_parser._address_lists == test_data['results']
