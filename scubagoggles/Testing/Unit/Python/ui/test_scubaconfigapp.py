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

    @pytest.fixture
    def generate_css_py(self):
        """Fixture providing path to generated CSS expected output."""
        return Path(__file__).parent / 'snippets' / 'generated_css.py'

    @pytest.mark.parametrize('dark, env', [
        (True, "1"),
        (False, ""),
    ])
    def test_generate_css(self, monkeypatch, generate_css_py, dark, env):
        """
        Tests that _generate_css either forces dark CSS or wraps it in the
        browser dark-mode media query, depending on the environment.
        """
        monkeypatch.setenv("SCUBAGOGGLES_UI_DARK", env)

        namespace = {}
        exec(generate_css_py.read_text(encoding="utf-8"), namespace)
        expected_css = namespace["EXPECTED_CSS"][dark]

        app = scubaconfigapp.ScubaConfigApp.__new__(scubaconfigapp.ScubaConfigApp)
        css = app._generate_css()

        assert css == expected_css


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
            # no valid baselines
            (
                {"baselines": "b1"},
                [],
                [],
                ["b1"],
                "⚠️ **Skipped unknown baselines:** b1"
            ),
            # baslines value not string or dict
            (
                {"baselines": 1}, # not a string or list
                [], # doesn't matter here
                [],
                [],
                ""
            ),
            # baslines value not string or dict
            (
                {"baselines": 1},
                [1], # shouldn't matter
                [],
                [],
                ""
            ),
            # no valid baselines
            (
                {"baselines": ["b1"]},
                ["b2", "b3", "b4"],
                [],
                ["b1"],
                "⚠️ **Skipped unknown baselines:** b1"
            ),
            # valid baselines are b1 and b2
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
            # no recognized keys
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
            # outputpath option
            (
                {"outputpath": "/tmp/path"},
                "outputpath",
                "/tmp/path"
            ),
            # darkmode options
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
            # quiet options
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
        Tests the Import output-related settings from the *config* attribute, 
        with various configurations
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
            # numberofuuidcharacterstotruncate in config
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
        # omitpolicy is present
        (
            {"omitpolicy": ["a", "b"]}, 
            {}
        ),
        (
            {"omitpolicy": {"a": "b"}}, 
            {"omitpolicy": {"a": "b"}}
        ),
        # breakglassaccounts in config
        (
            {"breakglassaccounts": ["a", "b"]}, 
            {"breakglassaccounts": ["a", "b"]}
        ),
        (
            {"breakglassaccounts": 1}, 
            {"breakglassaccounts": [1]}
        ),
        # preferreddohservers/preferreddnsresolvers in config
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

    @pytest.mark.parametrize(
        "yes_clicked,cancel_clicked,initial_state",
        [
            (True, False, {}),
            (True, False, {"alpha": "1", "beta": "2"}),
            (False, True, {}),
        ],
    )
    def test_show_reset_dialog(self, mocker, yes_clicked, cancel_clicked, initial_state):
        """Tests the reset confirmation dialog paths."""
        mock_warning = mocker.patch("streamlit.warning")
        mock_columns = mocker.patch("streamlit.columns")
        mock_button = mocker.patch(
            "streamlit.button",
            side_effect=[yes_clicked, cancel_clicked],
        )
        mock_rerun = mocker.patch("streamlit.rerun")

        session_state_mock = dict(initial_state)
        mocker.patch("streamlit.session_state", session_state_mock)

        col1 = mocker.MagicMock()
        col1.__enter__.return_value = col1
        col1.__exit__.return_value = False

        col2 = mocker.MagicMock()
        col2.__enter__.return_value = col2
        col2.__exit__.return_value = False

        mock_columns.return_value = [col1, col2]

        scubaconfigapp.ScubaConfigApp._show_reset_dialog.__wrapped__(
            scubaconfigapp.ScubaConfigApp.__new__(scubaconfigapp.ScubaConfigApp)
        )

        mock_warning.assert_called_once_with(
            "Are you sure you want to reset all fields to their defaults?\n\n"
            "All unsaved changes will be lost."
        )
        mock_columns.assert_called_once_with(2)
        mock_button.assert_any_call(
            "Yes, Reset", type="primary", key="confirm_reset_yes"
        )
        mock_button.assert_any_call("Cancel", key="confirm_reset_cancel")
        mock_rerun.assert_called_once()

        if yes_clicked:
            assert session_state_mock == {}
        else:
            assert session_state_mock == initial_state

    

    @pytest.mark.parametrize(
        "config_data,valid,err,expected_errors",
        [
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": ""}, True, "", []),
            
            ({"orgname": "",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": ""}, True, "",
                ["Organization Name is required."]),
           
            ({"orgname": "",
              "baselines": [],
              "credentials": "", "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": ""}, True, "", 
              ["Organization Name is required.", 
               "At least 1 product must be selected for the configuration to be valid."]),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": {}, "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": ""}, True, "", 
              []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "/tmp/creds.json",
              "outputpath": "", "breakglassaccounts": [], "subjectemail": ""}, False, 
              "Invalid credentials file", ["Invalid credentials file"]),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "/tmp/creds.json",
              "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": ""}, 
              True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": {}, "breakglassaccounts": [], 
              "subjectemail": ""}, 
              True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "./", "breakglassaccounts": [],
              "subjectemail": ""},
                True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "/tmp/out", "breakglassaccounts": [], 
              "subjectemail": ""}, 
              False, "Invalid output path", ["Invalid output path"]),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "/tmp/out", "breakglassaccounts": [], 
              "subjectemail": ""}, 
              True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": {}, 
              "subjectemail": ""}, 
              True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": ["admin@example.com"], 
              "subjectemail": ""}, 
              False, "Invalid break glass accounts", ["Invalid break glass accounts"]),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": ""}, 
              True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": "person@example.com"}, 
              True, "", []),
            
            ({"orgname": "Org",
              "baselines": ["gmail"],
              "credentials": "", "outputpath": "", "breakglassaccounts": [], 
              "subjectemail": "not-an-email"}, 
              False, "", ["Subject email has an invalid format."]),
        ],
    )
    def test_validate_before_save(self, mocker, config_data, valid, err, expected_errors):
        """
        Tests the _validate_before_save method.
        Ensures required configuration fields are validated and that each
        optional save-time validator branch is exercised independently.
        """
        session_state_mock = mocker.Mock()
        session_state_mock.config_data = config_data
        mocker.patch("streamlit.session_state", session_state_mock)

        mock_creds = mocker.patch.object(
            scubaconfigapp.ConfigValidator,
            "validate_credentials_file",
            return_value=(valid, err),
        )
        mock_output = mocker.patch.object(
            scubaconfigapp.ConfigValidator,
            "validate_output_path",
            return_value=(valid, err),
        )
        mock_break_glass = mocker.patch.object(
            scubaconfigapp.ConfigValidator,
            "validate_break_glass_accounts",
            return_value=(valid, err),
        )
        mock_email = mocker.patch.object(
            scubaconfigapp.ConfigValidator,
            "validate_email",
            return_value=valid,
        )

        app = scubaconfigapp.ScubaConfigApp.__new__(scubaconfigapp.ScubaConfigApp)
        errors = app._validate_before_save()

        assert errors == expected_errors

        if config_data.get("credentials", ""):
            mock_creds.assert_called_once_with(config_data["credentials"])
        else:
            mock_creds.assert_not_called()

        if config_data.get("outputpath", "") and config_data["outputpath"] != "./":
            mock_output.assert_called_once_with(config_data["outputpath"])
        else:
            mock_output.assert_not_called()

        if config_data.get("breakglassaccounts", []):
            mock_break_glass.assert_called_once_with(config_data["breakglassaccounts"])
        else:
            mock_break_glass.assert_not_called()

        if config_data.get("subjectemail", ""):
            mock_email.assert_called_once_with(config_data["subjectemail"])
        else:
            mock_email.assert_not_called()


    @pytest.mark.parametrize(
        "config_data,available_policies,expected_return_value",
        [
            (
                {"baselines": ["gmail"]},
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                {"Gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
            ),
            (
                {"baselines": ["gmail", "drive"]},
                {
                    "gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    "drive": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
                {
                    "Gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    "Drive": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
            ),
            (
                {"baselines": ["gMaIl"]},
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                {"Gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
            ),
            (
                {"baselines": []},
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                {},
            ),
            (
                {"baselines": None},
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                {},
            ),
            (
                {"baselines": ["gmail"]},
                {},
                {},
            ),
            (
                {"baselines": ["gmail"]},
                None,
                {},
            ),
            (
                {"baselines": ["calendar"]},
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                {},
            ),
            (
                {"baselines": ["gmail", "calendar", "drive"]},
                {
                    "gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    "drive": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
                {
                    "Gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    "Drive": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
            ),
            (
                {"baselines": ["Drive docs"]},
                {
                    "drive docs": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
                {
                    "Drive Docs": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
            ),
        ],
    )
    def test_get_selected_baseline_policies(
            self, mocker, config_data, available_policies, expected_return_value):
        """This function tests selected baselines to ensure they map to their available policies."""
        session_state_mock = mocker.Mock()
        session_state_mock.config_data = config_data
        mocker.patch("streamlit.session_state", session_state_mock)

        app = scubaconfigapp.ScubaConfigApp.__new__(scubaconfigapp.ScubaConfigApp)
        mocker.patch.object(app, "available_policies", available_policies, create=True)

        assert app._get_selected_baseline_policies() == expected_return_value

    @pytest.mark.parametrize(
        "session_data,key,type_error_on_parse,expected_session_state",
        [
            (
                {},
                "auditdate",
                False,
                {},
            ),
            (
                {"auditdate": 20260604},
                "auditdate",
                False,
                {"auditdate": 20260604},
            ),
            (
                {"auditdate": ["2026-06-04"]},
                "auditdate",
                False,
                {"auditdate": ["2026-06-04"]},
            ),
            (
                {"auditdate": "2026-06-04"},
                "auditdate",
                False,
                {"auditdate": scubaconfigapp.date(2026, 6, 4)},
            ),
            (
                {"auditdate": "not-a-date"},
                "auditdate",
                False,
                {},
            ),
            (
                {"auditdate": "2026-06-04"},
                "auditdate",
                True,
                {},
            )
        ],
    )
    def test_normalize_session_date(
            self, mocker, session_data, key, type_error_on_parse, expected_session_state):
        """Tests session date normalization for missing, invalid, and valid date values."""
        session_state_mock = dict(session_data)
        mocker.patch("streamlit.session_state", session_state_mock)

        if type_error_on_parse:
            datetime_mock = mocker.patch("scubagoggles.ui.scubaconfigapp.datetime")
            datetime_mock.strptime.side_effect = TypeError("Invalid date type")

        scubaconfigapp.ScubaConfigApp._normalize_session_date(key)

        assert session_state_mock == expected_session_state


    @pytest.mark.parametrize(
        "existing_data,config_key,session_key,before_session_state,expected_session_state",
        [
            # config_key missing; no session value exists to remove.
            (
                {},
                "auditdate",
                "session_auditdate",
                {},
                {},
            ),
            # config_key missing; stale session value is removed by else pop.
            (
                {},
                "auditdate",
                "session_auditdate",
                {"session_auditdate": scubaconfigapp.date(2026, 6, 4)},
                {},
            ),
            # config_key present with valid date string; session value is parsed.
            (
                {"auditdate": "2026-06-04"},
                "auditdate",
                "session_auditdate",
                {},
                {"session_auditdate": scubaconfigapp.date(2026, 6, 4)},
            ),
            # config_key present with invalid date string; ValueError removes stale value.
            (
                {"auditdate": "not-a-date"},
                "auditdate",
                "session_auditdate",
                {"session_auditdate": scubaconfigapp.date(2026, 6, 4)},
                {},
            ),
            # config_key present with wrong value type; TypeError removes stale value.
            (
                {"auditdate": ["2026-06-04"]},
                "auditdate",
                "session_auditdate",
                {"session_auditdate": scubaconfigapp.date(2026, 6, 4)},
                {},
            ),
            # existing_data has another key; requested config_key still follows else pop.
            (
                {"expiration": "2026-06-04"},
                "auditdate",
                "session_auditdate",
                {"session_auditdate": scubaconfigapp.date(2026, 6, 4)},
                {},
            ),
        ],
    )
    def test_load_existing_date(
            self, mocker, existing_data, config_key, session_key,
            before_session_state, expected_session_state):
        """Tests existing config date loading into session state."""
        session_state_mock = dict(before_session_state)
        mocker.patch("streamlit.session_state", session_state_mock)

        scubaconfigapp.ScubaConfigApp._load_existing_date(
            existing_data,
            config_key,
            session_key,
        )

        assert session_state_mock == expected_session_state


    @pytest.mark.parametrize(
        "existing_data,config_key,expected_value",
        [
            # config_key present with valid date string; parsed date is returned.
            (
                {"auditdate": "2026-06-04"},
                "auditdate",
                scubaconfigapp.date(2026, 6, 4),
            ),
            # config_key present with invalid date string; ValueError returns None.
            (
                {"auditdate": "not-a-date"},
                "auditdate",
                None,
            ),
            # config_key present with wrong value type; TypeError returns None.
            (
                {"auditdate": ["2026-06-04"]},
                "auditdate",
                None,
            ),
            # config_key missing from empty existing_data; None is returned.
            (
                {}, "auditdate", None
            ),
        ],
    )
    def test_parse_config_date(self, existing_data, config_key, expected_value):
        """Tests parsing config date strings into date values."""
        result = scubaconfigapp.ScubaConfigApp._parse_config_date(
            existing_data,
            config_key,
        )
        assert result == expected_value


    @pytest.mark.parametrize(
        "yaml_str,key,expected_flow",
        [
            # Empty key with non-list YAML does not change the string.
            ("orgname: Test Org\n", "", "orgname: Test Org\n"),
            # Empty YAML string has nothing to convert.
            ("", "baselines", ""),
            # Single-item block list converts to flow style.
            ("baselines:\n- gmail\n", "baselines", "baselines: [gmail]\n"),
            # Multi-item block list converts to flow style.
            (
                "baselines:\n- gmail\n- drive\n- calendar\n",
                "baselines",
                "baselines: [gmail, drive, calendar]\n",
            ),
        ],
    )
    def test_yaml_array_to_flow(self, yaml_str, key, expected_flow):
        """Tests YAML block list conversion to flow style."""
        result = scubaconfigapp.ScubaConfigApp._yaml_array_to_flow(
            yaml_str,
            key,
        )
        assert result == expected_flow


    @pytest.mark.parametrize(
        "pre_render_function,selected_baseline_policies,selected_baselines,"
        "available_policies,num_baseline_baseline_tabs",
        [
            # No baselines selected; no policy tabs are rendered.
            (
                False, {}, [],
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                0,
            ),
            # Pre-render runs independently before the no-baselines branch.
            (
                True, {}, [],
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                0,
            ),
            # Baselines selected, but baseline policy data is unavailable.
            (
                False, {}, ["gmail"], {}, 0,
            ),
            # Baselines and policy data exist, but selected baselines have no policies.
            (
                False, {}, ["gmail"],
                {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                0,
            ),
            # One selected baseline with policies renders one baseline tab.
            (
                False, {"Gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}},
                ["gmail"], {"gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"}}, 
                1,
            ),
            # Multiple selected baselines render matching tabs without pre-render.
            (
                False,
                {
                    "Gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    "Drive": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
                ["gmail", "drive"],
                {
                    "gmail": {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    "drive": {"GWS.DRIVE.1.1": "Restrict external sharing"},
                },
                2,
            ),
        ],
    )
    def test_render_policy_config_tab(
            self, mocker, pre_render_function, selected_baseline_policies,
            selected_baselines, available_policies, num_baseline_baseline_tabs):
        """Tests policy config tab branch rendering."""
        argument_dictionary = {'config_key': "omitpolicy",
        'prefix': "omit",
        'title': "Omit Policies",
        'help_content': "Help content",
        'description': "Description",
        'configured_label': "Omitted",
        'add_button_label': "Add Omission",
        'config_noun': "Omission",
        'field_map': {"rationale": "rationale", "expiration": "expiration"},
        'date_fields': {"expiration"}}

        render_form = mocker.Mock()
        render_summary = mocker.Mock()
        pre_render = mocker.Mock() if pre_render_function else None
        _POLICIES = {"GWS.TEST.1.1": {"rationale": "Already configured"}}

        session_state_mock = mocker.Mock()
        session_state_mock.config_data = {
            "baselines": selected_baselines,
            argument_dictionary["config_key"]: _POLICIES,
        }
        mocker.patch("streamlit.session_state", session_state_mock)

        expander_mock = mocker.MagicMock()
        mocker.patch("streamlit.expander", return_value=expander_mock)
        mocker.patch("streamlit.markdown")
        st_divider = mocker.patch("streamlit.divider")
        st_warning = mocker.patch("streamlit.warning")
        st_info = mocker.patch("streamlit.info")

        container_mock = mocker.Mock()
        st_container = mocker.patch("streamlit.container", return_value=container_mock)

        tab_mocks = [mocker.MagicMock() for _ in range(num_baseline_baseline_tabs)]
        st_tabs = mocker.patch("streamlit.tabs", return_value=tab_mocks)

        app = scubaconfigapp.ScubaConfigApp.__new__(scubaconfigapp.ScubaConfigApp)
        app.available_policies = available_policies
        mocker.patch.object(
            app,
            "_get_selected_baseline_policies",
            return_value=selected_baseline_policies,
        )
        render_policy_list = mocker.patch.object(app, "_render_baseline_policy_list")

        # render policy arguments
        render_policy_list_arguments = argument_dictionary.copy()
        render_policy_list_arguments["render_form"] = render_form
        render_policy_list_arguments["render_summary"] = render_summary
        render_policy_list_arguments["pre_render"] = pre_render
        app._render_policy_config_tab(
            **render_policy_list_arguments
        )

        if pre_render_function:
            pre_render.assert_called_once_with()
        else:
            assert pre_render is None

        if not selected_baselines:
            st_container.assert_called_once_with(border=True)
            container_mock.warning.assert_called_once()
            st_warning.assert_not_called()
            st_info.assert_not_called()
            st_divider.assert_not_called()
        elif not available_policies:
            st_warning.assert_called_once()
            container_mock.warning.assert_not_called()
            st_info.assert_not_called()
            st_divider.assert_not_called()
        elif not selected_baseline_policies:
            st_info.assert_called_once_with(
                "\u2139\ufe0f No policies available for selected products",
            )
            container_mock.warning.assert_not_called()
            st_warning.assert_not_called()
            st_divider.assert_not_called()
        else:
            if num_baseline_baseline_tabs == 1:
                st_tabs.assert_called_once_with(["Gmail"])
            elif num_baseline_baseline_tabs == 2:
                st_tabs.assert_called_once_with(["Gmail", "Drive"])
            
            p_list_args = {"config_key", "prefix", "configured_label", "add_button_label",
                           "config_noun", "field_map", "date_fields"}
            if num_baseline_baseline_tabs > 0:
                render_policy_list_args_ = {k: v for k, v in argument_dictionary.items() if k in p_list_args}
                render_policy_list_args_["render_form"] = render_form
                render_policy_list.assert_any_call(
                    "Gmail",
                    {"GWS.GMAIL.1.1": "Disable POP and IMAP access"},
                    _POLICIES,
                    **render_policy_list_args_,
                )
            if num_baseline_baseline_tabs == 2:
                render_policy_list_args_ = {k: v for k, v in argument_dictionary.items() if k in p_list_args}
                render_policy_list_args_["render_form"] = render_form
                render_policy_list.assert_any_call(
                    "Drive",
                    {"GWS.DRIVE.1.1": "Restrict external sharing"},
                    _POLICIES,
                    **render_policy_list_args_,
                )
            assert render_policy_list.call_count == num_baseline_baseline_tabs
            st_divider.assert_called_once_with()
        render_summary.assert_called_once_with(_POLICIES)
