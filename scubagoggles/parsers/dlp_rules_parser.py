"""Custom policy parser for Data Loss Protection (DLP) rules.
"""

import ast
import logging
import re

from collections import defaultdict
from enum import IntEnum
from functools import reduce

log = logging.getLogger(__name__)


class Likelihood(IntEnum):

    """This class defines the possible Likelihood values used by Google
    in DLP expressions.  UNKNOWN signifies an invalid/missing likelihood value,
    and is our value (not from Google).
    """

    UNKNOWN = 0
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

                log.debug('  no valid detectors found')

                continue

            log.debug('  valid detectors: %s', ', '.join(detectors))

            apps = self._check_apps(rule)

            app_blocking = self._check_blocking(rule)

            apps &= app_blocking

            # More than one rule may together cover all required PII detectors.

            for app in apps:
                app_detectors[app].update(detectors & self._minimum_detectors)

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
        using the "||" (OR) operator.  Each term must be for "all_content"
        and use the matches_dlp_detector().

        :return: a set containing one or more of the "minimum required"
            detectors found in the condition.
        :rtype: set
        """

        valid_detectors = set()

        condition = rule['condition']['contentCondition']

        if not cls._expression_re.match(condition):

            log.debug('  "%s" - expression not in expected format', condition)

            return valid_detectors

        # "Convert" the c++-ish OR (||) operators to Python (or).  The entire
        # condition should be able to be parsed with the AST parser - certainly
        # the conditions that are used for PII.  Conditions that can't be
        # parsed are ignored.

        condition = cls._or_re.sub(' or ', condition)

        try:
            expression = ast.parse(condition, mode='eval')
        except (SyntaxError, ValueError) as e:

            log.debug('  "%s" - unable to parse expression: %s',
                      condition,
                      e)

            return valid_detectors

        # Each term in the expression is call.  One call is examined at a
        # time.

        calls = []

        if isinstance(expression, ast.Expression):

            if (isinstance(expression.body, ast.BoolOp)
                and isinstance(expression.body.op, ast.Or)):

                calls = expression.body.values

            elif isinstance(expression.body, ast.Call):
                calls.append(expression.body)

        for item, call in enumerate(calls, 1):

            detector = cls._parse_detector(call, item)

            if detector:
                valid_detectors.add(detector)

        return valid_detectors

    @classmethod
    def _parse_detector(cls, call: ast.Call, item: int) -> str:

        """Given the parsed "call" data for a detector, this function
        examines the components to determine if this is a valid detector
        for PII content.

        :param ast.Call call: parsed call from Google condition expression.
        :param int item: position of call in expression, which is used for
            debug logging.

        :return: a string containing a valid detector, or an empty string
        if the call data doesn't satisfy the requirments for a detector.
        :rtype: str
        """

        error = False

        # The call must be of the form: all_content.matches_dlp_detector().

        if (not isinstance(call.func, ast.Attribute)
            or not isinstance(call.func.value, ast.Name)):

            log.debug('  condition %d: function not parsed', item)

            return ''

        content_type = call.func.value.id

        content = call.func.attr

        if content_type != 'all_content':

            log.debug('  condition %d: %s content type not '
                        '"all_content"',
                        item,
                        content_type)

            error = True

        if content != 'matches_dlp_detector':

            log.debug('  condition %d: %s condition is not '
                        '"detector"',
                        item,
                        content)

            error = True

        arguments_ok, detector = cls._check_arguments(call.args, item)

        return detector if arguments_ok and not error else ''

    @classmethod
    def _check_arguments(cls, arguments: list, item: int) -> tuple:

        """Returns a tuple which includes whether the arguments for the DLP
        condition match the expected values, and the detector name if the
        arguments are correct.

        :param list arguments: list of arguments parsed from the condition
            term.
        :param int item: position of call in expression, which is used for
            debug logging.

        :return: boolean indicating whether the condition term's arguments
            are correct, followed by the detector name specified in the
            term.
        :rtype: tuple
        """

        # The all_content.matches_dlp_detector() must have exactly 3 arguments.

        arguments_ok = len(arguments) == 3

        if not arguments_ok:

            log.debug('  condition %d: (%d != 3) unexpected argument count',
                      item,
                      len(arguments))

            return arguments_ok, ''

        # The first argument is the string detector name.

        detector = (arguments[0].value if isinstance(arguments[0], ast.Constant)
                    else '')

        # The second argument is the likelihood.  It is parsed as an enum
        # member of Likelihood.

        likelihood = (arguments[1].attr
                      if isinstance(arguments[1], ast.Attribute)
                      and arguments[1].value.attr == 'Likelihood'
                      else 'UNKNOWN')

        likelihood = (Likelihood[likelihood]
                      if likelihood in Likelihood.__members__
                      else Likelihood.UNKNOWN)

        # The third argument is a dictionary containing match counts.

        match_counts = (cls.convert_ast_dict(arguments[2])
                        if isinstance(arguments[2], ast.Dict) else {})

        # The arguments are correct if the likelihood is at least "likely"
        # or "greater" (e.g., "very likely"), and the minimum match counts
        # are 1.

        arguments_ok = detector in cls._minimum_detectors

        if arguments_ok:

            expected_match_counts = {'minimum_match_count': 1,
                                     'minimum_unique_match_count': 1}

            arguments_ok = (likelihood >= Likelihood.LIKELY
                            and match_counts == expected_match_counts)

            if not arguments_ok:
                log.debug('  condition %d: %s - invalid detector arguments:'
                          ' likelihood: %s, match counts: %s',
                          item,
                          detector,
                          likelihood,
                          match_counts)

        return arguments_ok, detector

    @staticmethod
    def convert_ast_dict(dictionary: ast.Dict) -> dict :

        """Converts an AST dictionary structure into a dictionary.

        :param ast.Dict: parsed dictionary.

        :return: Python dictionary created from the parsed dictionary data.
        :rtype: dict
        """

        try:
            result = {key.id if isinstance(key, ast.Name)
                    else ast.literal_eval(key): ast.literal_eval(value)
                    for key, value in zip(dictionary.keys, dictionary.values)}
        except Exception:
            result = {}

        return result

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
