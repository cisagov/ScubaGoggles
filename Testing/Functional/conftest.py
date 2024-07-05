import pytest

def pytest_addoption(parser):
    parser.addoption("--subjectemail", action="store")

@pytest.fixture 
def subjectemail(pytestconfig):
    return pytestconfig.getoption("subjectemail")