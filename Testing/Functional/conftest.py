import pytest
from SmokeTests.selenium_browser import Browser

def pytest_addoption(parser):
    parser.addoption("--subjectemail", action="store")
    parser.addoption("--domain", action="store")

@pytest.fixture 
def subjectemail(pytestconfig):
    return pytestconfig.getoption("subjectemail")

@pytest.fixture
def domain(pytestconfig):
    return pytestconfig.getoption("domain")

@pytest.fixture
def browser():
    browser_instance = Browser()
    yield browser_instance
    browser_instance.quit()