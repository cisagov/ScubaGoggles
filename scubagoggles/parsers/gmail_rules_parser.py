"""Custom policy parser for Gmail rules.
"""

import re

from collections import defaultdict

class GmailRulesParser:

    """This is the custom parser class for the Gmail spam override and
    blocked senders lists policy settings.
    """

    def __init__(self, policy_api, policies: dict):

        """Class constructor - this is called by the PolicyAPI during parser
        initialization.

        :param PolicyAPI policy_api: the PolicyAPI instance caller.
        :param dict policies: set of policies already processed by the
            PolicyAPI.
        """

        self._policy_api = policy_api
        self._policies = policies
        self._address_lists = self._gmail_address_lists()

    def __call__(self, orgunit: str, section: str):

        """The Gmail rules parser is invoked using the "call" method by the
        PolicyAPI instance.
        """

        self.gmail_rules(orgunit, section)

    def gmail_rules(self, orgunit: str, section: str):

        """This is the custom parser for the GMail "blocked sender" and
        "spam override" lists policies.

        These GMail policies consist of a list of entries, which in turn
        contain two different "senders" lists.  Each of these "senders"
        lists contain a list of email address LISTS!  The nested structure
        of this data makes it difficult to deal with in Rego code.  This
        parser examines and manipulates the policy data so that it is much
        easier to deal with in the Rego code for the baselines.

        :param str orgunit: name of the orgunit being parsed.
        :param str section: name of the policy section, which should indicate
            either the "blocked sender" or "spam override" lists section.
        """

        spam_override_lists = 'gmail_spam_override_lists'

        gmail_fields = {spam_override_lists:
                            {'setting': 'spamOverride',
                                'fields': ('bypassSenderAllowlist',
                                        'hideWarningBannerSenderAllowlist')},
                        'gmail_blocked_sender_lists':
                            {'setting': 'blockedSenders',
                                'fields': ('senderBlocklist',
                                        'bypassApprovedSenderAllowlist')}}

        # Collect the enabled rules for the orgunit.  This is a set of
        # rule identifiers for only the rules that are enabled.

        ou_policies = self._policies[orgunit]

        section_data = ou_policies.get(section)

        # No section data - the only way this happens is if the top orgunit
        # has no settings.

        if not section_data:
            return

        enabled_rules = self._enabled_rules(ou_policies)
        setting_name = gmail_fields[section]['setting']
        field_names = gmail_fields[section]['fields']

        # The senders list is traversed from the end to the beginning, so that
        # any disabled entry may be removed.

        gmail_rules = section_data.get(setting_name, ())

        for index, gmail_rule in reversed(tuple(enumerate(gmail_rules))):

            rule_id = gmail_rule['ruleId']

            if rule_id not in enabled_rules:
                del gmail_rules[index]
                continue

            for field_name in field_names:

                if field_name not in gmail_rule:
                    continue

                # Each element in the current list is a rule identifier that
                # references a list of email addresses.  To simplify the data,
                # the rule identifier is replaced by the actual email addresses
                # (as a structure with the list name and addresses).  The list
                # will be empty if the rule is disabled.

                email_addresses = []

                for rule_id in gmail_rule[field_name]:
                    email_addresses.append(self._address_lists[rule_id])

                gmail_rule[field_name] = email_addresses

        if section == spam_override_lists:
            self._gmail_domain_addr(section_data)

    def _gmail_domain_addr(self, spam_override_section: dict):

        """This method parses spam override lists to find any domains
        specified in email address lists.  There are rules that dictate that
        only email addresses and not domains belong in these lists.  Because
        the policy returned by Google contains levels of information (spam
        override lists containing allow lists containing email lists), it's
        far easier to do the domain detection and construct the domain list
        in Python than in Rego.

        Multiple allow lists in the spam override section are parsed by this
        method.  For each allow list, if any domain is found in the email
        lists, a new attribute is added containing a formatted string that
        indicates what spam override list, allow list(s), and containing
        email list(s) that include domains.  The presence of this attribute
        will indicate to the Rego code that there's a baseline violation.

        :param dict spam_override_section: portion of an orgunit's policies
            that contains the Gmail spam override lists.  If any domain is
            detected in the email lists, this dictionary will be modified to
            include the new attribute.
        """

        # Two sets of "allow" lists are parsed: the "hide warning banner"
        # sender allow list and the "bypass" selected senders allow list.
        # The following is a 2-element list - one for each allow list.
        # Each item is an attribute name.  The first is the name of the
        # attribute that enables/disables the allow list.  If the allow list
        # is disabled, no further parsing is done.  The second item is the
        # name of the allow list, and the third is the name of the attribute
        # to be created if any domains are found in the email lists.

        settings_list = (('hideWarningBannerFromSelectedSenders',
                          'hideWarningBannerSenderAllowlist',
                          'warningDomainsFound'),
                         ('bypassSelectedSenders',
                          'bypassSenderAllowlist',
                          'senderDomainsFound'))

        # For the user to be able to identify where the email lists
        # containing domains are located, the message is constructed with
        # the following format:
        #
        #   {<description>: [<email-list>: (<domain>, ...), ...], ...}
        #
        # where <description> is the description of the allow list as entered
        # by the user, <email-list> is the name of the email list (also
        # entered by the user), and <domain> is each domain name in the email
        # list.

        for setting_data in settings_list:

            enable, allow_list_name, message_name = setting_data

            override_listing = []

            for override in spam_override_section['spamOverride']:

                if not enable:
                    continue

                domains_list = []

                for allow_list in override.get(allow_list_name, ()):

                    # Extract domains from the email list.

                    domains = ', '.join(e for e in allow_list['list']
                                if re.match(r'^[^@]+\.[^@]+$', e))

                    if domains:

                        domains = f'{allow_list["name"]}: ({domains})'

                        domains_list.append(domains)

                if domains_list:

                    domains_list = ('{' + f'{override["description"]}: ['
                                    + ', '.join(domains_list) + ']}')

                    override_listing.append(domains_list)

            if override_listing:

                message = ', '.join(override_listing)

                spam_override_section[message_name] = message

    def _gmail_address_lists(self):

        """Examines the Gmail address lists for the top orgunit and creates
        a mapping of "rule id" to address list.  If the rule is not enabled,
        the address list will be empty.

        :param dict policies: dictionary of policies, keyed by orgunit name.
            This is the policies data structure constructed using Google's
            raw policy data after reduction and defaults have been applied.
        """

        top_ou_policies = self._policies[self._policy_api.top_orgunit]
        address_lists = defaultdict(dict)
        enabled_lists = self._enabled_rules(top_ou_policies)
        address_list_section = top_ou_policies.get('gmail_email_address_lists')

        if not address_list_section:
            return address_lists

        for list_entry in address_list_section.get('emailAddressList', ()):

            rule_id = list_entry['id']

            new_item = address_lists[rule_id]

            new_item['name'] = list_entry['name']

            address_list = list_entry.get('addressList',
                                          list_entry.get('blockedAddressList'))

            new_item['list'] = ([e['address'] for e in address_list['address']]
                                if rule_id in enabled_lists else [])

        return address_lists

    @staticmethod
    def _enabled_rules(ou_policies: dict) -> set:

        """Given an orgunit's policies, returns the set of enabled rule IDs
        for Gmail rules.

        :return: The set of rule IDs that are enabled in the given orgunit's
            policies.
        :rtype: set
        """

        rule_states_section = ou_policies.get('gmail_rule_states')

        if not rule_states_section:
            return set()

        return {e['ruleId'] for e in rule_states_section['ruleStates']
                if e['enabled']}
