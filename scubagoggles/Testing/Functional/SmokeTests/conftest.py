"""
    Fixtures for the Selenium smoke tests.  Their command-line options are
    registered in ../conftest.py.
"""

import pytest
from selenium_browser import Browser


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
