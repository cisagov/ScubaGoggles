"""Tests for the GmailRulesParser class.
"""

from pathlib import Path

from scubagoggles.parsers.gmail_rules_parser import GmailRulesParser
from scubagoggles.Testing.Unit.Python.test_policy_api import CommonMethods


def _spam_override_section(enabled: bool):

    """Builds a minimal spam override section with one "hide warning banner"
    allow list that contains a domain.  The enable flag is set per the
    argument so both the disabled and enabled cases can be exercised.
    """

    return {
        'spamOverride': [
            {
                'description': 'TestList',
                'hideWarningBannerFromSelectedSenders': enabled,
                'hideWarningBannerSenderAllowlist': [
                    {
                        'name': 'MyAllowList',
                        'list': ['evil.example.com']
                    }
                ]
            }
        ]
    }


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

    def test_gmail_domain_addr_disabled_allow_list(self):

        """A disabled spam override allow list must be skipped, even when it
        contains a domain, so no "domains found" marker is emitted.
        """

        # Bypass __init__, which needs a live Policy API; only the
        # _gmail_domain_addr method is under test here.
        parser = object.__new__(GmailRulesParser)
        section = _spam_override_section(enabled = False)

        parser._gmail_domain_addr(section)

        assert 'warningDomainsFound' not in section

    def test_gmail_domain_addr_enabled_allow_list(self):

        """An enabled allow list with a domain still emits the marker, so the
        disabled-list fix doesn't suppress real findings.
        """

        parser = object.__new__(GmailRulesParser)
        section = _spam_override_section(enabled = True)

        parser._gmail_domain_addr(section)

        assert section['warningDomainsFound'] == \
            '{TestList: [MyAllowList: (evil.example.com)]}'
