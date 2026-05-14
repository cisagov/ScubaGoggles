"""
test_scubaconfigapp.py tests the scubaconfigapp.py methods,
which are the methods of the ScubaConfigApp class
"""

import pytest
from scubagoggles.ui import scubaconfigapp
import types
import sys

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
