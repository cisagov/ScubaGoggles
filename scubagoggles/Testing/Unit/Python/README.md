# Python Unit Testing

This document provides background on how to run the Python unit tests for the `scubagoggles` Python package and covers key `pytest` concepts used in the test suite.

We focus on verifying the behavior of `scubagoggles` public class methods and how they interact together. Private helper methods are generally treated as implementation details and should be left untested. However, the exception to this rule is when private methods mutate shared state or encapsulate complex or high-importance logic. These cases warrant direct tests to test their observable behavior.

## Running Unit Tests

### Prerequisites

Install `pytest` and `pytest-mock` libraries to run the Python unit tests locally. 

To run all Python unit tests:

```bash
pytest ./scubagoggles/Testing/Unit/Python/
```

To run all tests for a specific file:

```bash
pytest ./scubagoggles/Testing/Unit/Python/reporter/test_reporter.py
```

To run an individual test by name:

```bash
pytest ./scubagoggles/Testing/Unit/Python -k test_create_html_table
```

## Test Naming Conventions

Name each unit test by prefixing `test_` to the corresponding class method's name.
For example, when testing the `Reporter.create_html_table` method, create `def test_create_html_table():` to keep tests consistent.

### Example Structure

```python
class TestReporter:
    def test_create_html_table(self):
        ...
```

## Pytest Concepts

### Fixtures

Fixtures provide reusable setup and teardown logic for tests. They are defined using the `@pytest.fixture` decorator and can be scoped to functions, classes, modules, or sessions.

```python
import pytest

@pytest.fixture
def sample_data():
    return {"key": "value"}
```

### Parametrize

`pytest.mark.parametrize` allows running a test function with multiple sets of arguments, improving coverage and reducing duplication.

```python
import pytest

@pytest.mark.parametrize("input,expected", [
    (1, 2),
    (2, 3),
])
def test_increment(input, expected):
    assert input + 1 == expected
```

### Monkeypatch

The `monkeypatch` fixture lets you modify or mock objects, functions, or environment variables during tests.

```python
def test_env_var(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    # test code that uses API_KEY
```

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/en/stable/)
- [Fixtures](https://docs.pytest.org/en/stable/how-to/fixtures.html)
- [Parametrize](https://docs.pytest.org/en/stable/how-to/parametrize.html)
- [Monkeypatch](https://docs.pytest.org/en/stable/how-to/monkeypatch.html)
