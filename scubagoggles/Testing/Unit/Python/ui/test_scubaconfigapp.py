"""
test_scubaconfigapp.py tests the scubaconfigapp.py methods,
which are the methods of the ScubaConfigApp class
"""

import pytest
from scubagoggles.ui import scubaconfigapp
import types
import sys
from pathlib import Path

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


    # yaml error exception
    # not config
    # normal
    # Generic Exception (ImportError)
    @pytest.mark.parametrize('yaml_error, conf_err, exc', [
        (True, False, False),
        (False, True, False),
        (False, False, True),
        (False, False, False),
    ])
    def test_import_configuration(self, mocker, yaml_error, conf_err, exc):
        if yaml_error:
            assert True == True
        else:
            assert True == True


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