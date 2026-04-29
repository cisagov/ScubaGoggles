"""Custom policy parser for Data Loss Protection (DLP) rules.
"""

import logging
import re

from collections import defaultdict
from enum import IntEnum
from functools import reduce

log = logging.getLogger(__name__)


class Likelihood(IntEnum):

    """This class defines the possible Likelihood values used by Google
    in DLP expressions.
    """

    VERY_UNLIKELY = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    VERY_LIKELY = 5


class DlpRulesParser:

    """This is the custom parser class for Data Loss Protection (DLP) rules.
    """

    # Regular expression definitions used in this class for parsing the
    # DLP rules.
    #
    # Matches <type>.<content><arguments> (with <arguments> containing
    # parentheses).

    _cond_regexp = r'([a-z_]+)\.([a-z_]+)(\([^)]+\))'

    # Matches "||" (OR).

    _or_regexp = r'\s*[|]{2}\s*'

    # Matches <term>[ || <term> ...]

    _expression_regexp = fr'(?i)^{_cond_regexp}(?:{_or_regexp}{_cond_regexp})*$'

    # Matches string used by Google for rule triggers.

    _app_re = re.compile(r'^google\.workspace\.(?P<app>\w+)\.(?P<type>\w+)\.'
                         r'\w+\.(?P<action>\w+)$')

    _cond_re = re.compile(_cond_regexp, re.IGNORECASE)

    _or_re = re.compile(_or_regexp)

    _expression_re = re.compile(_expression_regexp)

    _dict_key_re = re.compile(r'(?P<key>\w+):')

    # Matches string used by Google for likelihood levels.

    _likelihood_prefix_re = re.compile(r'google\.[\w.]+Likelihood\.')

    # These are the detectors for PII defined in the policy baseline(s).

    _minimum_detectors = {'CREDIT_CARD_NUMBER',
                          'US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER',
                          'US_SOCIAL_SECURITY_NUMBER'}

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

        """The DLP rules parser is invoked using the "call" method
        by the PolicyAPI instance.
        """

        self.dlp_rules(orgunit, section)

    def dlp_rules(self, orgunit: str, section: str):

        """This parser examines the rules in the given orgunit's policies,
        looking for one or more rules that block PII data identified in the
        policy baselines.

        If one or more active rules "cover" the minimum required detectors
        of PII, the apps (chat, gmail, and/or drive) with triggers for the
        rule(s) will be listed in the orgunit's policies under the "dlp_pii"
        section.  This list is to be used in the Rego code to determine
        policy conformance.

        :param str orgunit: name of the orgunit being parsed.
        :param str section: name of the policy section.
        """

        ou_policies = self._policies[orgunit]

        section_data = ou_policies.get(section)

        if not section_data:
            return

        app_detectors = defaultdict(set)

        for rule in section_data:

            if rule['state'] != 'ACTIVE' or not self._check_alerting(rule):
                continue

            log.debug('DLP rule: "%s"', rule['displayName'])

            detectors = self._check_condition(rule)

            if not detectors:
                continue

            apps = self._check_apps(rule)

            app_blocking = self._check_blocking(rule)

            apps &= app_blocking

            for app in apps:
                app_detectors[app] = detectors & self._minimum_detectors

        pii_apps = sorted(app for app, detectors in app_detectors.items()
                    if detectors == self._minimum_detectors)

        ou_policies['dlp_pii'] = pii_apps

        return

    @classmethod
    def _check_condition(cls, rule: dict) -> set:

        """Returns a set of "minimum required" detectors in the
        rule's data conditions that meets the Personally Identifiable
        Information (PII) requirements.  The DLP rules for the Policy API
        are discussed here:

        docs.cloud.google.com/identity/docs/
          concepts/supported-policy-api-settings#rules_and_detectors_settings

        The DLP conditions are expressed using Google's Common Expression
        Language (CEL).  Conditions with multiple terms are only supported
        using the "||" (OR) operator.  for the minimum detectors,

        :return: a set containing one or more of the "minimum required"
            detectors found in the condition.
        :rtype: set
        """

        valid_detectors = set()

        condition = rule['condition']['contentCondition']

        if not cls._expression_re.match(condition):

            log.debug('  %s - expression not in expected format', condition)

            return valid_detectors

        calls = cls._or_re.split(condition)

        for index, call in enumerate(calls):

            match = cls._cond_re.match(call)

            content_type, content, arguments = match.groups()

            arguments = cls._likelihood_prefix_re.sub('Likelihood.', arguments)

            arguments = cls._dict_key_re.sub(r'"\g<key>":', arguments)

            # ast.literal_eval() doesn't work in this case, not jumping thru
            # hoops to satisfy pylint as the following is no risk.
            # pylint: disable=eval-used

            arguments_ok, detector = eval(f'cls._check_arguments{arguments}')

            if arguments_ok:

                # The detector will only be included for the correct content
                # type and content.

                if (content_type == 'all_content'
                    and content == 'matches_dlp_detector'):
                    valid_detectors.add(detector)
                else:

                    item = index + 1

                    if content_type != 'all_content':

                        log.debug('  condition %d: %s content type not '
                                  '"all_content"',
                                  item,
                                  content_type)

                    if content != 'matches_dlp_detector':

                        log.debug('  condition %d: %s condition is not '
                                  '"detector"',
                                  item,
                                  content)

        return valid_detectors

    @classmethod
    def _check_arguments(cls,
                         detector: str,
                         likelihood: Likelihood,
                         match_counts: dict) -> tuple:

        """Returns a tuple which includes whether the arguments for the DLP
        condition match the expected values, and the detector name if the
        arguments are correct.

        :return: boolean indicating whether the condition term's arguments
            are correct, followed by the detector name specified in the
            term.
        :rtype: tuple
        """

        # The arguments are correct if the likelihood is at least "likely"
        # or "greater" (e.g., "very likely"), and the minimum match counts
        # are 1.

        arguments_ok = (detector in cls._minimum_detectors
                        and likelihood >= Likelihood.LIKELY
                        and match_counts['minimum_match_count'] == 1
                        and match_counts['minimum_unique_match_count'] == 1)

        return arguments_ok, detector

    @classmethod
    def _check_apps(cls, rule: dict) -> set:

        """For each app, there are one or more triggers that must be enabled.
        This method returns the apps that have triggers for the given rule.

        :param dict rule: current DLP rule settings.

        :return: apps that are triggers for the given rule.
        :rtype: set
        """

        valid_triggers = {'chat': {'attachment_upload', 'message_send'},
                          'drive': {'file_share'},
                          'gmail': {'email_send'}}

        # For each rule trigger, extract the app name, type, and action,
        # and assemble them in a dictionary the same as the valid triggers.

        found_triggers = defaultdict(set)

        for trigger in rule['triggers']:

            match = cls._app_re.match(trigger)

            if not match:
                continue

            app = match['app']

            app_type = match['type']

            action = match['action']

            found_triggers[app].add(f'{app_type}_{action}')

        # The app names are returned for rule triggers that match the valid
        # trigger list.

        apps = {a for a, v in found_triggers.items()
                if v == valid_triggers.get(a)}

        return apps

    @staticmethod
    def _check_alerting(rule: dict) -> bool:

        """Returns True if alerts are enabled for the given DLP rule.

        :param dict rule: current DLP rule settings.

        :return: True if alerts are enabled; False otherwise.
        :rtype: bool
        """

        # When alerts are enabled, the only indication is that the
        # "alertCenterConfig" setting is present (even if it's just
        # an empty dictionary).  This setting is missing when alerts
        # are disabled.

        alert_action = rule['action']['alertCenterAction']

        return alert_action.get('alertCenterConfig') is not None

    @classmethod
    def _check_blocking(cls, rule: dict) -> set:

        """This method returns the apps that have blocked content according
        to the baseline.  For each app, there is a list of key names
        into "sub-dictionaries" under rule['action'] that have parameters
        that should all be True.  In the case of Drive/Docs, there are
        no parameters, but the empty dictionary must exist.

        :param dict rule: current DLP rule settings.

        :return: the names of apps configured for blocking content.
        :rtype: set
        """

        expected_blocking = {'chat': (('blockContent', 'actionParams'),
                                      ('applyExternalDirectMessages',
                                       'applyExternalGroupChats',
                                       'applyExternalRooms')),
                             'drive': (('blockAccess',), None),
                             'gmail': (('blockContent', 'actionParams'),
                                       ('applyExternalMessages',
                                        'applyInternalMessages'))}

        apps = {app for app, info in expected_blocking.items()
                if cls._is_blocked(rule['action'].get(f'{app}Action'), *info)}

        return apps

    @staticmethod
    def _is_blocked(action: dict, keys: tuple, param_names: tuple) -> bool:

        """Returns True if the current app's configured action indicates the
        content is to be blocked.

        :param dict action: dictionary containing the current app's actions.
        :param keys tuple: an ordered list of keys that allow traversal in
            the given dictionary to the sub-dictionary containing the
            blocking configuration.
        :param param_names tuple: zero of more parameter names that are keys
            in the blocking configuration dictionary and whose values are
            boolean flags expected to be True.

        :return: True if content is to be blocked; False otherwise.
        :rtype: bool
        """

        if not action:
            return False

        # Wind down the dictionary "hierarchy" to locate the dictionary
        # identified in the keys.  'params' contains one of 2 values:
        # it's set to the 'missing' dictionary if one or more keys aren't
        # found; or it contains the dictionary (either with params or empty).

        missing = {'missing': True}

        params = reduce(lambda d, k: d.get(k, missing) if d else missing,
                        keys,
                        action)

        # The dictionary can be empty (in the Drive/Docs case), but it can't
        # be missing.  If parameter names are given, all parameters in the
        # dictionary must exist and be set to True to indicate the blocking
        # is enabled.

        return (params != missing
                and (param_names is None
                     or all(params.get(n) for n in param_names)))
