"""
test_scubaconfigapp.py tests the scubaconfigapp.py methods,
which are the methods of the ScubaConfigApp class
"""

import pytest
from scubagoggles.ui import scubaconfigapp
import types
import sys
from pathlib import Path
from yaml import YAMLError

class TestScubaConfig:
    """Unit tests for the ScubaGoggles Config Class"""

    @pytest.mark.parametrize('raiseImportError', [
            (True),
            (False)
        ]
    )
    def test_load_scubagoggles_backend(self, mocker, raiseImportError):
        """
        Verifies the _load_scubagoggles_backend loads the correct version,
        or the fallback if the backend is not installed
        """
        # mocked classes in (success) case where no ImportError is Raised
        # can be anything (should be different from ImportError case)
        class MockImportUserConfig: 
            def __init__(self):
                self.output_dir = "home"
                self.credentials_file = "tmp/creds"

        class MockImportVersion:
            number = "2.0.0"
            
            # ensure this is different from the 
            # ImportError mocked class
            # (initialize returns None in that case)
            @classmethod
            def initialize(cls):
                return True

        # expected results without Exception
        pkg = types.ModuleType("scubagoggles")
        pkg.__path__ = []

        config_mod = types.ModuleType("scubagoggles.config")
        config_mod.UserConfig = MockImportUserConfig

        version_mod = types.ModuleType("scubagoggles.config")
        version_mod.Version = MockImportVersion

        if raiseImportError:
            # setting these to None will raise an ImportError
            pkg = None
            config_mod = None
            version_mod = None

        # this should patch imports with the "mocked" objects
        mocker.patch.dict(sys.modules, {
            "scubagoggles": pkg,
            "scubagoggles.config": config_mod,
            "scubagoggles.version": version_mod,
        })

        # run our tests
        success, user_conf, version = scubaconfigapp.ScubaConfigApp._load_scubagoggles_backend()

        assert (raiseImportError == success) is False
        
        if raiseImportError:
            assert user_conf().output_dir == "./"
            assert user_conf().credentials_file is None
            assert version.number == "1.0.0"
            assert version.initialize() is None
        else:
            # without ImportError
            assert user_conf().output_dir == "home"
            assert user_conf().credentials_file == "tmp/creds"
            assert version.number == "2.0.0"
            assert version.initialize() is True
    
    # def test_generate_css()

    @pytest.mark.parametrize('prod_mds, os_err', [
        ([Path('gmail.md'), Path('drive.md')], True),
        ([Path('gmail.md'), Path('drive.md')], False),
        ([], False),
    ])
    def test_parse_baseline_policies(self, mocker, prod_mds, os_err):
        """
        Verifies the parse_basline function returns the controls by
        product for each baseline, or an empty dictionary if none are
        specified or an exception is raised
        """
        mocker.patch.object(Path, "exists", return_value=True)
        mocker.patch.object(Path, "glob", return_value=iter(prod_mds))

        expected = {}

        markdown_parser_mock = mocker.patch('scubagoggles.reporter.md_parser.MarkdownParser')
        markdown_instance = markdown_parser_mock.return_value

        if prod_mds:
            parse_baseline_ret_val = {
                "gmail": "gmail baselines",
                "drive": "drive baselines",
            }
            markdown_instance.parse_baselines.return_value = parse_baseline_ret_val

            controls_by_product_ret_val = {
                'gmail': {"gmail control": "gmail control data"},
                'drive': {"drive control": "drive control data"},
            }
            markdown_instance.controls_by_product.return_value = controls_by_product_ret_val
            
            expected = {}

            if os_err:
                markdown_instance.parse_baselines.side_effect = OSError("OS Error")
                expected = {}

        assert expected == scubaconfigapp.ScubaConfigApp.parse_baseline_policies()

    @pytest.mark.parametrize('yaml_error, conf_err, exc', [
        (True, False, False),
        (False, True, False),
        (False, False, True),
        (False, False, False),
    ])
    def test_import_configuration(self, mocker, yaml_error, conf_err, exc):
        """
        Tests that the import_configuration method properly handles exceptions
        and loads configurations properly
        """
        mock_file = mocker.Mock()
        if yaml_error:
            mock_st_error = mocker.patch('streamlit.error')
            mock_file.read.side_effect = YAMLError("Error")
            sconf_app = scubaconfigapp.ScubaConfigApp()
            sconf_app.import_configuration(mock_file)
            mock_st_error.assert_called_once_with("❌ YAML parsing error: Error")
        elif conf_err:
            mock_st_error = mocker.patch('streamlit.error')
            mock_file.read.return_value = b''
            sconf_app = scubaconfigapp.ScubaConfigApp()
            sconf_app.import_configuration(mock_file)
            mock_st_error.assert_called_once_with("Invalid or empty YAML file")
        elif exc:
            mock_file.read.return_value = b'baselines: baseline data'
            # name error Exception?
            mock_import_org_fields = mocker.patch.object(scubaconfigapp.ScubaConfigApp, 
                                                         '_import_org_fields')
            # generic Exception
            mock_import_org_fields.side_effect = NameError("streamlit Name Error")
            st_err_mock = mocker.patch('streamlit.error')
            sconf_app = scubaconfigapp.ScubaConfigApp()
            sconf_app.import_configuration(mock_file)
            st_err_mock.assert_called_once_with("❌ Import error: streamlit Name Error")
        else:
            mock_file.read.return_value = b'baselines: baseline data'
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_import_org_fields')
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_import_auth_fields')
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_import_baselines')
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_import_output_settings')
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_import_advanced_settings')
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_import_policy_and_account_sections')
            mocker.patch.object(scubaconfigapp.ScubaConfigApp, '_show_import_summary')
            st_rerun_mock = mocker.patch('streamlit.rerun')
            sconf_app = scubaconfigapp.ScubaConfigApp()
            sconf_app.import_configuration(mock_file)
            st_rerun_mock.assert_called_once()

    @pytest.mark.parametrize('config_dict, expected', [
        ({'B': "baseline data"}, {'baselines': "baseline data"}),
        ({'o': "out.txt"}, {'outputpath': "out.txt"}),
        ({'BaseLines': "baseline data"}, {'baselines': "baseline data"}),
        ({'credentials': "creds.txt"}, {'credentials': "creds.txt"}),
        ({'c': "credentials.txt", 'OUT': "out.txt", 'policies': "baseline data"}, 
         {'credentials': "credentials.txt", 'out': "out.txt", 'policies': "baseline data"})
    ])
    def test_normalize_config_keys(self, config_dict, expected):
        """
        Tests that _normalize_config_keys expands key aliases and lowercases key values
        """
        result = scubaconfigapp.ScubaConfigApp._normalize_config_keys(config_dict)
        assert expected == result

    @pytest.mark.parametrize('config, expected', [
        (
            {'A':"1", 'B':"2"},
            {}
        ),
        (
            {'orgunitname': "OrgUnit"},
            {'orgunitname': "OrgUnit"}
        ),
        (
            {'orgunitname': "OrgUnit", 'description': "Desc", 'A':"1"},
            {'orgunitname': "OrgUnit", 'description': "Desc"}
        )
    ])
    def test_import_org_fields(self, mocker, config, expected):
        """
        Tests that organization-level fields are imported into session state
        """

        # class inheritance
        class MockSessionState(dict):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.config_data = {}
        
        mock_session_state = MockSessionState({})

        mocker.patch("streamlit.session_state", mock_session_state)
        scubaconfigapp.ScubaConfigApp._import_org_fields(config)
        
        assert mock_session_state == expected


    @pytest.mark.parametrize('config, baseline_info, ' \
    'valid_baselines, invalid_baselines, msg', [
            (
                {"not baselines": "nb1"},
                [], # shouldn't matter
                [], # shouldn't matter
                [], # shouldn't matter
                ""
            ),
            (
                {"baselines": "b1"},
                 #doesn't need to be a dictionary, only care about mocking the return value
                ["b1"],
                ["b1"],
                [],
                ""
            ),
            (
                {"baselines": "b1"},
                [],
                [],
                ["b1"],
                "⚠️ **Skipped unknown baselines:** b1"
            ),
            (
                {"baselines": 1}, # not a string or list
                [], # doesn't matter here
                [],
                [],
                ""
            ),
            (
                {"baselines": 1},
                [1], # shouldn't matter
                [],
                [],
                ""
            ),
            (
                {"baselines": ["b1"]},
                ["b2", "b3", "b4"],
                [],
                ["b1"],
                "⚠️ **Skipped unknown baselines:** b1"
            ),
            (
                {"baselines": ["b1", "b2", "b3", "b4"]},
                ["b1", "b2", "b5"],
                ["b1", "b2"],
                ["b3", "b4"],
                "⚠️ **Skipped unknown baselines:** b3, b4"
            )
        ]
    )
    def test_import_baselines(self, mocker, config, baseline_info, invalid_baselines, 
                              valid_baselines, msg):
        """
        Tests that the import_baselines function and ensure 
        correct validations are called/configured
        """

        mock_sync_baseline_checkboxes = mocker.patch.object(scubaconfigapp.ScubaConfigApp,
                                                             '_sync_baseline_checkboxes')
        mocker.patch("streamlit.session_state")
        st_warning = mocker.patch("streamlit.warning")
        get_baseline_info = mocker.patch.object(scubaconfigapp.ScubaConfigApp,
                                                'get_baseline_info')
        get_baseline_info.return_value = baseline_info
        sconf_app = scubaconfigapp.ScubaConfigApp()
        sconf_app._import_baselines(config)

        if "baselines" in config:
            mock_sync_baseline_checkboxes.assert_called_once_with(valid_baselines)
            if msg:
                st_warning.assert_called_once_with(msg)
        else:
            mock_sync_baseline_checkboxes.assert_not_called()
            st_warning.assert_not_called()

    @pytest.mark.parametrize('config, key, expected_value', [
            (
                {}, # empty dictionary
                None,
                None
            ),
            (
                # keys not used by import output settings
                {"random_key": "random_value"},
                None,
                None
            ),
            (
                {"outputpath": "/tmp/path"},
                "outputpath",
                "/tmp/path"
            ),
            (
                {"darkmode": "true"},
                "darkmode",
                True
            ),
            (
                {"darkmode": "TrUe"},
                "darkmode",
                True
            ),
            (
                {"darkmode": "abc123"},
                "darkmode",
                False
            ),
            (
                {"darkmode": []},
                "darkmode",
                False
            ),
            (
                {"darkmode": [1, 2, 3]},
                "darkmode",
                True
            ),
            (
                {"quiet": "non-empty string"},
                "quiet",
                True
            ),
            (
                {"quiet": ""},
                "quiet",
                False
            ),
            (
                {"quiet": ""},
                "quiet",
                False
            )
        ]
    )    
    def test_import_output_settings(self, mocker, config, key, expected_value):
        """
        Tests the Import output-related settings from the *config* attribute
        """
        session_state_mock = mocker.patch("streamlit.session_state")
        session_state_mock.config_data = {}
        scubaconfigapp.ScubaConfigApp._import_output_settings(config)
        if key is not None:
            assert key in session_state_mock.config_data
            assert session_state_mock.config_data[key] == expected_value
        else:
            # no dictionary modifications were made to config_data
            assert session_state_mock.config_data == {}


    @pytest.mark.parametrize('config, expected_data', [
            (
                # key not in list of specified keys (in method scope)
                {"random_key": "random_value"},
                {}
            ),
            (
                {"outjsonfilename": "output.json"},
                {"outjsonfilename": "output.json"}
            ),
            (
                # convert to string example
                {"accesstoken": 12345},
                {"accesstoken": "12345"}
            ),
            (
                {"numberofuuidcharacterstotruncate": "not an int"},
                {}
            ),
            (
                {"numberofuuidcharacterstotruncate": "4"},
                {"numberofuuidcharacterstotruncate": 4}
            ),
            (
                {"regopath": Path("/path/to/rego"), "random_key": "random_value", 
                 "numberofuuidcharacterstotruncate": "not an int"},
                {"regopath": str(Path("/path/to/rego"))}
            )
        ]
    )
    def test_import_advanced_settings(self, mocker, config, expected_data):
        """
        Test Advanced Import settings, and ensure they are configured properly
        """
        session_state_mock = mocker.patch("streamlit.session_state")
        session_state_mock.config_data = {}
        scubaconfigapp.ScubaConfigApp._import_advanced_settings(config)
        assert session_state_mock.config_data == expected_data


    @pytest.mark.parametrize('value, coerce, expected_return_value', [
        (["b1"], None, ["b1"]),   # instance is list (non-empty)
        ([], None, []),           # instance is list (empty)
        ("123", None, ["123"]),   # truthy value, coerce default None
        ("123", int, [123]),      # truthy value, coerce int, gets converted
        (None, None, []),         # falsy value, coerce default None
        ("", str, []),            # second falsy case, coerce str
    ])
    def test_normalize_to_list(self, value, coerce, expected_return_value):
        """
        Test the normalize_to_list function works as intended and test different 
        edge cases.
        """
        assert scubaconfigapp.ScubaConfigApp._normalize_to_list(value, coerce) == expected_return_value


    @pytest.mark.parametrize('config, expected_value', [
        # individual cases
        (
            {}, 
            {}
        ),
        (
            {"omitpolicy": ["a", "b"]}, 
            {}
        ),
        (
            {"omitpolicy": {"a": "b"}}, 
            {"omitpolicy": {"a": "b"}}
        ),
        (
            {"breakglassaccounts": ["a", "b"]}, 
            {"breakglassaccounts": ["a", "b"]}
        ),
        (
            {"breakglassaccounts": 1}, 
            {"breakglassaccounts": [1]}
        ),
        (
            {"preferreddohservers": ('a', 'b')}, 
            {"preferreddohservers": ["('a', 'b')"]}
        ),
        (
            {"preferreddohservers": "string", "preferreddnsresolvers": [1, 2]},
            {"preferreddohservers": ["string"], "preferreddnsresolvers": [1, 2]}
        ),
        (
            {"skipdoh": ""},
            {"skipdoh": False}
        ),
        (
            {"skipdoh": "123"}, 
            {"skipdoh": True}
        ),
        # mixed cases
        # ignored keys
        (
            {"omitpolicy": {1: 2}, "preferreddohservers": 1, "ignored_key": "ignored_value"}, 
            {"omitpolicy": {1: 2}, "preferreddohservers": ["1"]}
        ),
        # multiple specified keys
        (
            {"omitpolicy": "abcdef", "skipdoh": ""},
            {"skipdoh": False}
        )
    ])
    def test_import_policy_and_account_sections(self, mocker, config, expected_value):
        """
        Tests the import_policy_and_account_sections() function
        This unit test handles different branching cases related to when the 
        config attribute (streamlit session state) should be updated.
        """
        session_state_mock = mocker.patch("streamlit.session_state")
        session_state_mock.config_data = {}

        scubaconfigapp.ScubaConfigApp._import_policy_and_account_sections(config)

        assert session_state_mock.config_data == expected_value

        if "skipdoh" in config:
            session_state_mock.__setitem__.assert_called_once_with(
                "skipdoh_checkbox", bool(config["skipdoh"])
            )
        else:
            session_state_mock.__setitem__.assert_not_called()


    @pytest.mark.parametrize("uploaded", [
            True,
            False
        ])
    def test_show_import_dialog(self, mocker, uploaded):
        """
        Tests the _show_import_dialogue function
        """
        import_configuration_mock = mocker.patch.object(
            scubaconfigapp.ScubaConfigApp, "import_configuration")

        session_state_mock = mocker.patch("streamlit.session_state")
        # example return value
        session_state_mock.get.return_value = 0

        uploaded_file = mocker.Mock()
        # arbitrary name
        uploaded_file.name = "config.yaml"

        file_uploader_mock = mocker.patch(
            "streamlit.file_uploader",
            return_value=uploaded_file if uploaded else None,
        )
        success_mock = mocker.patch("streamlit.success")

        scubaconfigapp.ScubaConfigApp._show_import_dialog.__wrapped__(
            scubaconfigapp.ScubaConfigApp.__new__(scubaconfigapp.ScubaConfigApp)
        )

        file_uploader_mock.assert_called_once_with(
            "Upload a YAML configuration file",
            type=["yaml", "yml"],
            key="config_file_uploader_0",
        )
        session_state_mock.get.assert_called_once_with("uploader_gen", 0)

        if uploaded:
            assert session_state_mock.uploader_gen == 1
            success_mock.assert_called_once_with(
                "✅ **config.yaml** loaded successfully — importing..."
            )
            import_configuration_mock.assert_called_once_with(uploaded_file)
        else:
            assert "uploader_gen" not in session_state_mock.__dict__
            success_mock.assert_not_called()
            import_configuration_mock.assert_not_called()

    #@pytest.mark.parametrize("", [
    #        True,
    #        False
    #    ])
    #def test_show_reset_dialog(self, mocker, uploaded):
    #

    #@pytest.mark.parametrize("", [
    #        True,
    #        False
    #    ])
    #def test_validate_before_save(self, mocker, uploaded):
    #

