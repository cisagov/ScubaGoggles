import pytest
from selenium import webdriver

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
    driver = webdriver.Chrome()
    yield driver
    driver.quit()