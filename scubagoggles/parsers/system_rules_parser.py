"""Custom policy parser for system defined rules.
"""

import logging

log = logging.getLogger(__name__)

# This is the complete list of system-defined rules.  The dictionary is keyed
# on the rule's "display name", and the value is the rule summary description.
# The names and descriptions are taken directly from Google and must match
# exactly.
#
# The set of rules is divided into two groups: active and inactive.  These
# are the default states.

ACTIVE_RULE_DEFAULTS = {
    'Account suspension warning':
        'Google Workspace accounts engaging in suspicious activity may '
        'have their account suspended. Google Workspace accounts must '
        'comply with the Google Workspace Terms of Service, Google '
        'Workspace for Education Terms of Service, Google Cloud '
        'Platform Terms of Service or Cloud Identity Terms of '
        'Service.',
    'Device compromised':
        'Provides details about devices in your domain that have entered '
        'a compromised state.',
    'Domain data export initiated':
        'A Super Administrator for your Google account has started '
        'exporting data from your domain.',
    'Gmail potential employee spoofing':
        'Incoming messages where a sender\'s name is in your Google '
        'Workspace directory, but the mail is not from your company\'s '
        'domains or domain aliases.',
    'Google Operations':
        'Provides details about security and privacy issues that affect '
        'your Google Workspace services.',
    'Government-backed attacks':
        'Warnings about potential government-backed attacks.',
    'Leaked password':
        'Google detected compromised credentials requiring a reset of the '
        'user\'s password.',
    'Malware message detected post-delivery':
        'Messages detected as malware post-delivery that are '
        'automatically reclassified.',
    'Phishing in inboxes due to bad whitelist':
        'Messages classified as spam by Gmail filters delivered to user '
        'inboxes due to whitelisting settings in the Google Admin console '
        'that override the spam filters.',
    'Phishing message detected post-delivery':
        'Messages detected as phishing post-delivery that are '
        'automatically reclassified.',
    'Spike in user-reported spam':
        'An unusually high volume of messages from a sender that users '
        'have marked as spam.',
    'SSO profile added':
        'Alerts you when a new SSO profile allows users to sign in to '
        'Google services through your third-party identity provider.',
    'SSO profile updated':
        'Alerts you when there\'s a change to the SSO profile that allows '
        'users to sign in to Google services through your third-party '
        'identity provider.',
    'Super admin password reset':
        'Alerts you when the password for a super admin account changes. '
        'This admin can manage all features in your Admin console and '
        'Admin APIs.',
    'Suspicious device activity':
        'Provides details if device properties such as device ID, serial '
        'number, type of device, or device manufacturer are updated.',
    'Suspicious login':
        'Google detected a sign-in attempt that doesn\'t match a user\'s '
        'normal behavior, such as a sign-in from an unusual location.',
    'Suspicious message reported':
        'A sender has sent messages to your domain that users have '
        'classified as spam.',
    'Suspicious programmatic login':
        'Google detected suspicious login attempts from potential '
        'applications or computer programs.',
    'User suspended (Google identity alert)':
        'Google detected suspicious activity and suspended the account.',
    'User suspended due to suspicious activity':
        'Google suspended a user\'s account due to a potential compromise '
        'detected.',
    'User suspended for spamming through relay':
        'Google detected suspicious activity such as spamming through a '
        'SMTP relay service and suspended the account.',
    'User suspended for spamming':
        'Google detected suspicious activity such as spamming and '
        'suspended the account.',
    'User-reported phishing':
        'A sender has sent messages to your domain that users have '
        'classified as phishings.'}

INACTIVE_RULE_DEFAULTS = {
    'Calendar settings changed':
        'An admin has changed Google Workspace Calendar settings.',
    'Drive settings changed':
        'An admin has changed Google Workspace Drive settings.',
    'Email settings changed':
        'An admin has changed Google Workspace Gmail settings.',
    'Mobile settings changed':
        'An admin has changed mobile management settings.',
    'Rate limited recipient':
        'A high rate of incoming email indicating a potential malicious '
        'attack or misconfigured setting.',
    'User granted Admin privilege':
        'A user is granted an admin privilege.',
    'User\'s Admin privilege revoked':
        'A user is revoked of their admin privilege.'}

# This is the complete dictionary of system-defined rules, sorted by the
# name to keep traversal consistent.

SYSTEM_RULES = dict(sorted((ACTIVE_RULE_DEFAULTS
                            | INACTIVE_RULE_DEFAULTS).items()))


class SystemRulesParser:

    """This is the custom parser class for system defined rules.
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

    def __call__(self, orgunit: str, section: str):

        """The system defined rules parser is invoked using the "call" method
        by the PolicyAPI instance.
        """

        self.system_rules(orgunit, section)

    def system_rules(self, orgunit: str, section: str):

        """This is the custom parser for the system-defined rules policies.

        System-defined rules consist of a list of entries, and include only
        the rules that have been created and/or modified by the administrator.
        This parser removes any user-defined rules and adds default
        system-defined rules.

        :param str orgunit: name of the orgunit being parsed.
        :param str section: name of the policy section, which should indicate
            either the "blocked sender" or "spam override" lists section.
        """

        if orgunit != self._policy_api.top_orgunit:
            log.warning('? unexpected system defined rules for orgunit: %s',
                        orgunit)

        ou_policies = self._policies[orgunit]

        section_data = ou_policies.get(section)

        if section_data is None:

            section_data = ou_policies[section] = []

        # Google's Policy API returns only system-defined rules that are
        # modified from the default value by the administrator.  The rules
        # also include those that are "user-defined".  We're going to do
        # two things: first, collect the returned rules and remove any
        # user-defined rules.  Any code (e.g., Rego) processing these rules
        # can assume that the set includes only system-defined rules.
        # Second, add default system-rules for those that have not been
        # modified from the default (and therefore not present in the
        # returned rules).  Downstream code can expect this section to
        # contain the complete set of system-defined rules.

        found_rules = {r['displayName']: i for i, r in enumerate(section_data)}

        if found_rules and log.isEnabledFor(logging.DEBUG):

            log.debug('system-defined rules returned by Policy API:')

            for rule in sorted(found_rules):
                log.debug('  %s', rule)

        indices = {i: r for r, i in found_rules.items()
                   if r not in SYSTEM_RULES}

        for index in reversed(indices):

            log.debug('"%s" - removing "non-baseline" rule from policies',
                      indices[index])

            del section_data[index]

        # FYI, if any rule was deleted above, the other indices in "found_rules"
        # will most likely be invalid.  Currently, the indices are not needed
        # at this point.

        for state, rules_set in (('ACTIVE', ACTIVE_RULE_DEFAULTS),
                                 ('INACTIVE', INACTIVE_RULE_DEFAULTS)):

            default_rules = [{'displayName': name,
                              'description': description,
                              'state': state}
                             for name, description in rules_set.items()
                             if name not in found_rules]

            section_data += default_rules
