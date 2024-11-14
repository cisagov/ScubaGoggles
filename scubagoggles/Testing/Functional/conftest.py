"""
    conftest.py serves as a configuration file for pytest.
"""

import pytest
from SmokeTests.selenium_browser import Browser


def pytest_addoption(parser):
    """
        Add custom cli arguments when running `pytest`.

        Args:
            parser: An instance of "argparse.ArgumentParser"
    """
    parser.addoption("--subjectemail", action="store")
    parser.addoption("--customerdomain", action="store")


@pytest.fixture
def subjectemail(pytestconfig):
    """
        Setup code that shares the "subjectemail" parameter across tests.

        Args:
            pytestconfig: Provides access to the "Config" object for a current test session
    """
    return pytestconfig.getoption("subjectemail")


@pytest.fixture
def customerdomain(pytestconfig):
    """
        Setup code that shares the "customerdomain" parameter across tests.

        Args:
            pytestconfig: Provides access to the "Config" object for a current test session
    """
    return pytestconfig.getoption("customerdomain")


@pytest.fixture
def browser():
    """
        Setup code that shares a Selenium WebDriver instance across tests.
    """
    browser_instance = Browser()
    yield browser_instance
    browser_instance.quit()
