# Python Unit Testing

## Overview

This document tracks the approach and tools used for unit testing the `scubagoggles` Python package. It covers files and tests, as well as key `pytest` concepts leveraged in our test suite.

## Key Pytest Concepts

### Fixtures

Fixtures provide reusable setup and teardown logic for tests. They are defined using the `@pytest.fixture` decorator and can be scoped to functions, classes, modules, or sessions.

```python
import pytest

@pytest.fixture
def sample_data():
    return {"key": "value"}
```

Use fixtures by declaring them as arguments in your test functions.

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

## Running Unit Tests

To run all Python unit tests:

```bash
pytest ./Testing/Python/
```

To run all tests for a specific file:

```bash
pytest ./Testing/Python/reporter/test_reporter.py
```

To run an individual test by name:

```bash
pytest ./Testing/Python -k test_create_html_table
```

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/en/stable/)
- [Fixtures](https://docs.pytest.org/en/stable/how-to/fixtures.html)
- [Parametrize](https://docs.pytest.org/en/stable/how-to/parametrize.html)
- [Monkeypatch](https://docs.pytest.org/en/stable/how-to/monkeypatch.html)