"""Tests for the PolicyAPI class.
"""

import json
import re

from pathlib import Path

import pytest

# The import is needed as stated and not how pylint wants it.
# pylint: disable=consider-using-from-import

import google.auth.transport.requests as requests
import scubagoggles.auth as auth

from scubagoggles.parsers.gmail_rules_parser import GmailRulesParser
from scubagoggles.policy_api import PolicyAPI


class CommonMethods:

    """Common methods related to PolicyAPI class testing used in this module
    and other testing modules.
    """

    def __init__(self, data_dir: Path):

        """CommonMethod class initialization - the data directory containing
        data needed by tests is given.
        """

        self._data_dir = data_dir

    def next_test_data(self, test_prefix: str):

        """Given a prefix of file names, this method yields the file name
        (considered the test name) and the test data as a dictionary which is
        read from the file in the data directory.  The file name format is:
        <prefix><test-number>, with <test-number> as an integer (1, 2, ...
        - any combination of digits following the prefix works, but you should
        follow the convention of starting with 1 and increasing sequentially
        for each subsequent test).

        :yield: (test_name, test_data)
        :rtype: tuple
        """

        for input_file in self._data_dir.glob(f'{test_prefix}*.json'):
            test_name = input_file.stem
            if not re.match(fr'{test_prefix}\d+$', test_name):
                continue

            test_data = json.loads(input_file.read_text())
            yield test_name, test_data

    @staticmethod
    def patch_policy_api(monkeypatch, test_data: dict = None):

        """Sets up the PolicyAPI class so it can be used with test methods.
        The given test data must include a dictionary with optional keys
        "orgunits" and "groups" that may contain a set of orgunit and group
        names, respectively.  These take the place of the PolicyAPI class
        calling Google for those names.
        """

        def mock_get_ou(_):
            return test_data.get('orgunits') if test_data else None

        def mock_get_groups(_):
            return test_data.get('groups') if test_data else None

        monkeypatch.setattr(PolicyAPI, '_get_ou', mock_get_ou)
        monkeypatch.setattr(PolicyAPI, '_get_groups', mock_get_groups)


class MockGwsAuth:

    """Mocks the GwsAuth class - the tests in this module do not call any
    Google API.
    """

    # pylint: disable=missing-function-docstring
    # pylint: disable=too-few-public-methods

    @property
    def credentials(self):
        return None


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

# pylint: disable=too-many-public-methods


class TestPolicyApi:

    """This class contains unit tests for the PolicyAPI class.
    """

    # The test module needs to access "internal" methods.
    # pylint: disable=protected-access

    _common = CommonMethods(Path(__file__).parent / 'data')

    def test_close(self, monkeypatch):

        """Tests that the AuthorizedSession is closed when the PolicyAPI is
        used as a context manager.  Closing the session causes the resources
        to be cleaned up.
        """

        self._common.patch_policy_api(monkeypatch)

        with PolicyAPI(auth.GwsAuth(), 'topOU') as policy_api:
            session = policy_api._session

        assert session._close_count == 1

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              (True, True),
                              (False, True),
                              # Invalid values
                              (1100, False),
                              ('true', False),
                              ('False', False)))
    def test_isbool(self, value, expected):

        """Tests for the isBool() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isBool(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              ('TEST', True),
                              ('TRUSTED_DOMAINS', True),
                              # Invalid values
                              (32768, False),
                              ('192.168.0.1', False)))
    def test_isenum(self, value, expected):

        """Tests for the isEnum() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isEnum(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              (50, True),
                              (-463, True),
                              # Invalid values
                              (3.14, False),
                              ('TEST', False)))
    def test_isint(self, value, expected):

        """Tests for the isInt() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isInt(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              ([{'a': 1, 'b': 2}, {1: 'a', '2': 'b'}], True),
                              # Invalid values
                              ([1, 2, 3], False),
                              (2, False),
                              ('test', False)))
    def test_islistdict(self, value, expected):

        """Tests for the isListDict() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isListDict(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              (['one', 'two', 'three'], True),
                              # Invalid values
                              ([1, 2, 3], False),
                              (['four', 6, 'six'], False),
                              ('test', False)))
    def test_isliststrings(self, value, expected):

        """Tests for the isListStrings() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isListStrings(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              ('enabled', True),
                              ('disabled', True),
                              ('EnAblEd', True),
                              ('disABLEd', True),
                              # Invalid values
                              ('NOTHING', False),
                              ('disable', False)))
    def test_isstate(self, value, expected):

        """Tests for the isState() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isState(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              ('test', True),
                              ('disabled', True),
                              # Invalid values
                              (True, False),
                              (82, False)))
    def test_isstring(self, value, expected):

        """Tests for the isString() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isString(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              ('5s', True),
                              ('24h', True),
                              ('7m', True),
                              # Invalid values
                              (2, False),
                              ('tomorrow', False),
                              ('7z', False),
                              ('-2d', False),
                              ('4months', False),
                              ('3d', False),
                              ('8.5h', False)))
    def test_isduration(self, value, expected):

        """Tests for the isDuration() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isDuration(value) is expected

    @pytest.mark.parametrize(('value', 'expected'),
                             (# Valid values
                              ('2025-02-24T17:40:27.050Z', True),
                              ('2032-04-13T06:34:27Z', True),
                              # Invalid values
                              ('2012-10-312T17:40:0Z', False),
                              ('22-', False)))
    def test_istimestamp(self, value, expected):

        """Tests for the isTimestamp() lambda used in the PolicyAPI expected
        settings.
        """

        assert PolicyAPI.isTimestamp(value) is expected

    def test_expected_settings(self):

        """Tests the PolicyAPI expected settings data structure.
        """

        expected_settings = PolicyAPI._expectedPolicySettings

        for section_name, section_data in expected_settings.items():
            assert isinstance(section_name, str)

            # Each section must contain settings, and optionally a reducer.

            settings_found = False

            for name, value in section_data.items():
                assert name in ('key', 'parser', 'settings', 'reducer')

                match name:
                    case 'settings':

                        settings_found = True

                        # Each setting must contain a validator.

                        for setting_name, validator in value.items():
                            assert isinstance(setting_name, str)
                            assert validator in (PolicyAPI.isBool,
                                                 PolicyAPI.isDuration,
                                                 PolicyAPI.isEnum,
                                                 PolicyAPI.isInt,
                                                 PolicyAPI.isListDict,
                                                 PolicyAPI.isListStrings,
                                                 PolicyAPI.isState,
                                                 PolicyAPI.isString,
                                                 PolicyAPI.isTimestamp)

                    case 'parser':
                        assert value in (GmailRulesParser,)

                    case 'reducer':
                        assert value in (PolicyAPI._max_map_reducer,
                                         PolicyAPI._merge_reducer,)

            assert settings_found, f'section: {section_name}'

    def test_default_value(self):

        """Tests the default values in the PolicyAPI class.
        """

        expected_settings = PolicyAPI._expectedPolicySettings

        # For each default value, it must belong to a valid section and
        # setting (as defined in the expected policy settings data structure).
        # The default value itself must pass the validator.

        for section_name, section_data in PolicyAPI._defaults.items():
            section_settings = expected_settings[section_name]['settings']

            for setting_name, setting_default in section_data.items():
                assert section_name in expected_settings
                assert setting_name in section_settings

                validator = section_settings[setting_name]
                assert validator(setting_default)

    def test_parser_map(self, monkeypatch, subtests):

        """Tests the initialization of the PolicyAPI parser map.
        """

        module = globals()
        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('policyapi_parsermap'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch)
                expected_settings = test_data['expected_settings']
                monkeypatch.setattr(PolicyAPI,
                                    '_expectedPolicySettings',
                                    expected_settings)
                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')

                # For custom parsers, the name of the parser class is stored
                # in the test input and is converted here from the string
                # value to the parser class.

                for config in expected_settings.values():

                    parser = config.get('parser')

                    if parser in module and isinstance(module[parser], type):
                        config['parser'] = module[parser]

                policies = test_data['policies']

                if ('expect_exception' in test_data
                    and test_data['expect_exception']):
                    with pytest.raises(RuntimeError):
                        policy_api._initialize_parser_map(policies)
                else:
                    policy_api._initialize_parser_map(policies)
                    self._compare_parser_map(policy_api, test_data)

    def test_get_groups(self, monkeypatch, subtests):

        """Tests the Policy API method for getting GWS groups and storing
        them internally in the '_group_id_map'.
        """

        monkeypatch.setattr(PolicyAPI, '_get_ou', lambda x: None)

        next_test_data = self._common.next_test_data

        for test_name, test_data in next_test_data('policyapi_get_groups'):
            with subtests.test(msg = f'subtest: {test_name}'):
                self._patch_get(monkeypatch, test_data)
                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                result = policy_api._group_id_map
                assert result == test_data['results']

    def test_get_policies(self, monkeypatch, subtests):

        """Tests the Policy API method for converting the raw policy data
        returned by Google to the format used by ScubaGoggles for Rego.
        """

        # Individual tests are made by running ScubaGoggles with appropriate
        # settings that tests the desired functionality.  Use the environment
        # variable SCUBAGOGGLES_DUMP_FILE to set up a file where the raw
        # response from the Google Policy API will be written (JSON).  Use
        # an existing test data file as a template for a new file.  It's
        # ideal if you can trim the response down to the relevant policies
        # (otherwise, all policies are going to be in the test and it'll
        # make it more difficult to debug when there are problems).  Put the
        # "dumped" response in the "response" section of the test data file.
        # You may have to edit the "orgunits", "groups", "defaults", and
        # "service_status" sections as needed (sometimes the easiest is to
        # try to make these small or empty).  Run pytest with --trace and
        # stop at the "assert" line.  Dump the result into JSON format.
        # Confirm that the result is correct for the given input and then
        # use it in the "results" section of the test data.

        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('policyapi_get_policies'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch, test_data)
                self._patch_get(monkeypatch, test_data)
                self._patch_service_status(monkeypatch, test_data)
                test_defaults = test_data['defaults']
                monkeypatch.setattr(PolicyAPI, '_defaults', test_defaults)
                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                result = policy_api.get_policies()
                assert result == test_data['results']

    def test_get_ou(self, monkeypatch, subtests):

        """Tests the Policy API method for getting GWS orgunits and storing
        them internally in the '_orgunit_id_map'.
        """

        monkeypatch.setattr(PolicyAPI, '_get_groups', lambda x: None)

        next_test_data = self._common.next_test_data

        for test_name, test_data in next_test_data('policyapi_get_ou'):
            with subtests.test(msg = f'subtest: {test_name}'):
                self._patch_get(monkeypatch, test_data)
                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                result = policy_api._orgunit_id_map
                assert result == test_data['results']

    def test_verify(self, monkeypatch, subtests):

        """Tests the PolicyAPI verify() method for ensuring that policy
        setting values are the expected type.  Test data is stored in
        JSON-formatted files in the "data" subdirectory.  This includes
        the input policy settings and the expected list of invalid
        settings.
        """

        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('policyapi_verify'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch, test_data)
                expected_settings = test_data['expected_settings']
                self._add_validators(expected_settings)
                monkeypatch.setattr(PolicyAPI,
                                    '_expectedPolicySettings',
                                    expected_settings)
                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                missing_policies = policy_api.verify(test_data['policies'])
                self._compare_verify(missing_policies, test_data)

    def test_verify_novalue(self, monkeypatch, caplog):

        """Tests the simple case where the Policy API verify() method
        is provided with no policy settings for the top-level orgunit.
        """

        top_ou = 'topOU'
        self._common.patch_policy_api(monkeypatch, {'orgunits': {top_ou}})
        expected_message = f'No policy settings found for orgunit: {top_ou}'

        policy_api = PolicyAPI(auth.GwsAuth(), top_ou)
        policy_api.verify({})

        assert len(caplog.records) == 1
        assert caplog.records[0].message == expected_message

    def test_reducer(self, monkeypatch, subtests):

        """Tests the Policy API reduction of policy data.  Test data is
        stored in JSON-formatted files in the "data" subdirectory.  The
        data is manually generated by extracting portions of real data
        returned by Google's Policy API - see the dump() method in the
        policy_api module.  The expected results are produced by calling
        the PolicyAPI _reduce() method using the input data, and then
        calling _write_reduction() in this module to write the JSON to
        be included in the test input data.
        """

        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('policyapi_reducer'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch, test_data)

                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                policy_api._reduce(test_data['policies'])

                self._compare_reduction(policy_api, test_data)

    def test_apply_defaults(self, monkeypatch, subtests):

        """Tests the method of the Policy API that applies default values
        to policy settings in the top-level orgunit when certain settings
        are missing.  Test data includes a set of defaults to apply, the
        policy settings, and the expected result once the defaults have
        been applied.
        """

        next_test_data = self._common.next_test_data
        patch_policy_api = self._common.patch_policy_api

        for test_name, test_data in next_test_data('policyapi_defaults'):
            with subtests.test(msg = f'subtest: {test_name}'):
                patch_policy_api(monkeypatch, test_data)
                test_defaults = test_data['defaults']
                monkeypatch.setattr(PolicyAPI, '_defaults', test_defaults)
                self._patch_service_status(monkeypatch, test_data)

                policy_api = PolicyAPI(auth.GwsAuth(), 'topOU')
                policy_api._apply_defaults(test_data['policies'])

                self._compare_defaults(test_data)

    @staticmethod
    def _compare_defaults(test_data: dict):

        """Compares the result of applying policy setting defaults with the
        expected result from the test data.
        """

        policies = test_data['policies']
        results = test_data['results']
        assert policies == results

    @staticmethod
    def _compare_parser_map(policy_api: PolicyAPI, test_data: dict):

        """Compares the PolicyAPI's parser map with the expected result
        from the test data.
        """

        # Any custom parsers used in testing must be imported into this module.
        # Each instance in the parser map must be an instance of the parser
        # class named in the expected result section of the test data.

        module = globals()

        expected_results = test_data['results']

        for section, parser_instance in policy_api._parser_map.items():

            assert section in expected_results

            parser_class = module[expected_results[section]]

            assert isinstance(parser_instance, parser_class)

    @staticmethod
    def _compare_reduction(policy_api: PolicyAPI, test_data: dict):

        """Compares the result of a policy reduction with the expected
        result from the test data.
        """

        # Because the test data is stored as a JSON-formatted file, the
        # key for the policy reduction map was converted to a slash (/)
        # separated string and this needs to be converted to a tuple
        # before the comparison.

        expected_result = {tuple(k.split('/')): v
                           for k, v in test_data['results'].items()}
        assert policy_api._reduction_map == expected_result

    @staticmethod
    def _compare_verify(missing_policies: set, test_data: dict):

        """Compares the result of policy setting verification with the
        expected result from the test data.
        """

        expected_result = sorted(test_data['results'])
        assert sorted(missing_policies) == expected_result

    @staticmethod
    def _write_reduction(policy_api: PolicyAPI, temp_file: Path):

        """Used to generate test data by writing the policy reduction map
        produced by the PolicyAPI's _reduce() method.  Use the written JSON
        data to cut/paste it into the test input data, which should already
        include the orgunits, groups, and policy data for the test.
        """

        # The key for the reduction map is a tuple, which isn't supported in
        # JSON, so this is converted into a string key, with the components
        # of the tuple separated by a slash (/).

        save_dict = {'results': {'/'.join(k): v
                                 for k, v in policy_api._reduction_map.items()}}

        with temp_file.open('w', encoding = 'utf-8') as out_stream:
            json.dump(save_dict, out_stream, indent = 2)

    @staticmethod
    def _patch_get(monkeypatch, test_data: dict):

        """Patches the PolicyAPI::_get() method, which gets the Policy API
        data from Google.  The given test data is used to simulate the
        response from the Policy API "get" request.  Depending on the given
        test data, it simulates either a single-page or multi-page responses.
        """

        def multi_get(_, _unused_url, params):

            # This simulates multi-page responses.  The test data must contain
            # a "responses" (plural) section and all but the last response
            # must contain a "nextPageToken".

            next_token = 'nextPageToken'
            responses = test_data.get('responses')
            if not responses:
                return None
            if not params or 'pageToken' not in params:
                return responses[0]

            for index, response in enumerate(responses):
                if (next_token in response
                    and response[next_token].startswith(params['pageToken'])):
                    return responses[index + 1]

            raise RuntimeError('missing or mismatched next page token')

        def single_get(*_):

            # This simulates a single-page response.  The test data must
            # contain a "response" (singular) section.

            return test_data.get('response')

        mock_get = multi_get if 'responses' in test_data else single_get

        monkeypatch.setattr(PolicyAPI, '_get', mock_get)

    @staticmethod
    def _patch_service_status(monkeypatch, test_data: dict):

        """Adds the service status expected Policy API settings using
        the list of services in the test data.  This allows the test to
        have a predictable number of expected services.
        """

        services = test_data.get('service_status', ())

        # To insulate the testing somewhat from changes made by Google over
        # time, we remove the service status settings from the expected set
        # and replace them with specific settings defined for the test.

        expected_settings = {k: v for k, v
                             in PolicyAPI._expectedPolicySettings.items()
                             if not k.endswith('_service_status')}

        for service in services:
            service_status = f'{service}_service_status'
            expected_settings[service_status] = {'settings':
                                                 {'serviceState':
                                                  PolicyAPI.isState}}

        monkeypatch.setattr(PolicyAPI,
                    '_expectedPolicySettings',
                    expected_settings)

    @staticmethod
    def _add_validators(expected_settings: dict):

        """Given expected policy settings from test data that includes
        the verifier as a string, this method replaces the verifier
        string with the function from the PolicyAPI class that
        performs the verification.
        """

        for section_data in expected_settings.values():
            expected_settings = section_data['settings']
            for setting_name, verifier_name in expected_settings.items():
                verifier = getattr(PolicyAPI, verifier_name)
                expected_settings[setting_name] = verifier
