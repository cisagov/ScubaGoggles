import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

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
    driver = webdriver.Chrome(options=chrome_options)
    yield driver
    driver.quit()