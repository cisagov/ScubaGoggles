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

@pytest.fixture
def subjectemail(pytestconfig):
    """
        Setup code that shares the "subjectemail" parameter across tests.

        Args:
            pytestconfig: Provides access to the "Config" object for a current test session
    """
    return pytestconfig.getoption("locations")
