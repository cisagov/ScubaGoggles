"""
    conftest.py serves as a configuration file for pytest.
"""

import pytest

def pytest_addoption(parser):
    """
        Add custom cli arguments when running `pytest`.

        Args:
            parser: An instance of "argparse.ArgumentParser"
    """
    parser.addoption("--locations", nargs="+", action="store")
    parser.addoption("--repo_home", action="store")

@pytest.fixture
def locations(pytestconfig):
    """
        Setup code that shares the "locations" parameter across tests.

        Args:
            pytestconfig: Provides access to the "Config" object for a current test session
    """
    return pytestconfig.getoption("locations")

@pytest.fixture
def repo_home(pytestconfig):
    """
        Setup code that shares the "repo_home" parameter across tests.

        Args:
            pytestconfig: Provides access to the "Config" object for a current test session
    """
    return pytestconfig.getoption("repo_home")
