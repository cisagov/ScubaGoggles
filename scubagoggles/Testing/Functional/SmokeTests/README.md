# ScubaGoggles Functional Smoke Testing Automation
The ScubaGoggles repository consists of an automation suite to help test the functionality of the ScubaGoggles tool itself. The test automation is geared towards contributors who want to execute the functional smoke testing orchestrator as part of their development/testing activity.

This README outlines the ScubaGoggles software test automation structure and its usage. The document also contains instructions for adding new tests to the existing automation suite if necessary.

## Table of Contents
- [Smoke Testing Prerequisites](#smoke-testing-prerequisites)
  - [Pytest and Selenium](#pytest-and-selenium)
  - [Google Service Account](#google-service-account)
- [Functional Smoke Testing Structure](#functional-smoke-testing-structure)
  - [Smoke Testing Classes and Methods](#smoke-testing-classes-and-methods)
  - [Automated workflow via GitHub Actions](#automated-workflow-via-github-actions)
- [Functional Smoke Testing Usage](#functional-smoke-testing-usage)
  - [Running in a Local Development Environment](#running-in-a-local-development-environment)
  - [Running Remotely via GitHub Actions](#running-remotely-via-github-actions)
- [Adding New Tests](#adding-new-tests)

## Smoke Testing Prerequisites ##
Running the ScubaGoggles functional smoke tests requires a Windows, MacOS, or Linux computer or VM. The development environment should have Python v3.10.x installed at a minimum ([refer to our installing Python dependencies documentation if its not already installed](https://github.com/cisagov/ScubaGoggles/blob/main/docs/installation/DownloadAndInstall.md#installing-python-dependencies)), Pytest, and Selenium installed locally.

### Pytest and Selenium ###
Pytest is a Python testing framework which is commonly used for unit, integration, and functional testing. ([Pytest Get Started](https://docs.pytest.org/en/stable/getting-started.html))

Selenium supports automation of all the major browsers in the market through the use of WebDriver. ([Selenium Get Started](https://www.selenium.dev/documentation/webdriver/getting_started/))

To install Pytest and Selenium on your development environment, open a new terminal session and run the following command:

```
pip install pytest selenium
```

> [!NOTE]
> The functional smoke tests use Chrome as its WebDriver when running Selenium tests. [Setup ChromeDriver](https://developer.chrome.com/docs/chromedriver/get-started) if you don't already have the Google Chrome web browser installed.

### Google Service Account ###
The ScubaGoggles functional smoke tests must be executed with a service account. [Refer to our service account documentation on how to get setup.](https://github.com/cisagov/ScubaGoggles/blob/main/docs/authentication/ServiceAccount.md#using-a-service-account)

A `credentials.json` file is required at the root directory of the ScubaGoggles project if running the functional smoke tests in a local development environment.

Take note of the `subjectemail`, the email used to authenticate with GWS that has necessary administrator permissions, and the GWS `customerdomain` that ScubaGoggles is run against. Both credentials are required in a later step.

## Functional Smoke Testing Structure ##
ScubaGoggles functional smoke testing has two main components: the smoke testing orchestrator and the automated workflow run via GitHub Actions.

### Smoke Testing Classes and Methods ###
The smoke testing orchestrator ([/Testing/Functional/SmokeTests/smoke_test.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test.py)) executes each test declared inside the `SmokeTest` class. The tests currently cover:
- if the `scubagoggles gws` command generates valid output for all baselines
- if ScubaResults.json contains API errors or exceptions
- if the generated baseline reports, i.e. BaselineReports.html, CalendarReport.html, ChatReport.html, etc., contain valid content and all links redirect accordingly

The smoke testing utils ([/Testing/Functional/SmokeTests/smoke_test_utils.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test_utils.py)) stores helper methods which perform various operations.

The Selenium Browser class ([/Testing/Functional/SmokeTests/selenium_browser.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/selenium_browser.py)) encapsulates the setup, usage, and teardown of Selenium WebDriver instances.

The Pytest configuration methods ([/Testing/Functional/SmokeTests/conftest.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/conftest.py)) declare various Pytest fixtures, allowing for the use of CLI arguments when invoking the Pytest command.

### Automated Workflow via GitHub Actions ###
The automated workflow for running the functional smoke tests ([/.github/workflows/run_smoke_test.yml](https://github.com/cisagov/ScubaGoggles/blob/main/.github/workflows/run_smoke_test.yml)) is triggered on `push` events to the main branch, `pull_request` events when a pull request is opened/reopened/reviewed, and manually with custom user input via workflow_dispatch.

## Functional Smoke Testing Usage ##
After completing all of the prerequisite steps, the functional smoke tests can be run in a local development environment or remotely via GitHub Actions.

### Running in a Local Development Environment ###
> [!IMPORTANT]
> Ensure that you have correctly setup a Google service account and that the `credentials.json` stored at the root directory of the ScubaGoggles project is up to date. If you haven't already, please refer back to the [prerequisite step on Google Service Accounts](#google-service-account) for how to setup before proceeding.

The following arguments are required when running the functional smoke tests:
- `--subjectemail="user@domain.com"` (the email used to authenticate with GWS, must have necessary administrator permissions)
- `--customerdomain="domain.com"` (the domain that ScubaGoggles is run against)

Replace `user@domain.com` with your email and `domain.com` with your domain, then run the following command to execute the functional smoke tests:
```
pytest ./Testing/Functional/SmokeTests/ -vvv --subjectemail="user@domain.com" --customerdomain="domain.com"
```

Common Pytest parameters and their use cases:
- `-v` or `--verbose` (shows individual test names and results)
- `-vv` (increases verbosity further, shows detailed output about each test)
- `-vvv` (shows even more detailed output and debug-level information)
- `-s` (disables output capturing allowing print() statements and logs to be shown in the console)
- `-k` (run tests that match a keyword)

    Example (only runs test_scubagoggles_output, deselects the rest):
    ```
    pytest ./Testing/Functional/SmokeTests/ -vvv -k test_scubagoggles_output --subjectemail="user@domain.com" --customerdomain="domain.com"
    ```

- `--tb=short`, `tb=long`, or `tb=no` (provide either brief, full, or suppress the traceback output for failed tests)
- `-q` (reduces output to show only minimal information)

Run `pytest -h` for a full list of CLI options or [learn more about Pytest usage here.](https://docs.pytest.org/en/7.1.x/how-to/usage.html)

### Running Remotely via GitHub Actions ###
Go to the [run_smoke_test.yml workflow](https://github.com/cisagov/ScubaGoggles/actions/workflows/run_smoke_test.yml) in the GitHub Actions tab, then click the "Run workflow" dropdown button.

The default values are the following:
- ref branch: `main` but can be set to any branch
- operating system: `['windows-latest', 'macos-latest']` ([list of supported GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/using-github-hosted-runners/about-github-hosted-runners#standard-github-hosted-runners-for-public-repositories))
- python version: `['3.10']`
- opa version: "0.60.0"

![Screenshot (226)](https://github.com/user-attachments/assets/6f25b7a9-3981-4866-a413-93df4bae1130)

Feel free to play around with the inputs then click the "Run workflow" button when ready. The workflow will create a matrix strategy for each combination. For example, passing `['windows-latest', 'macos-latest']`, `['3.10', '3.11', 3.12']`, and OPA version `0.60.0` will create the following:

![Screenshot (218)](https://github.com/user-attachments/assets/212b4e4b-d552-4dc9-a3f6-7f0e29accc4b)

Some factors to consider:
- Each input is required so an empty string will fail validation. `[]`, `['']`, `['', ]` may also cause the workflow to error out, although this is expected behavior.
- `ubuntu-latest` has not been tested as a value for operating system. Support can be added for this, although its dependent on if this is something we want to test for ScubaGoggles as a whole.
- Python versions <3.10.x are not supported and will cause the smoke test workflow to fail.
- [Due to the lack of an array input type from GitHub](https://github.com/orgs/community/discussions/11692), the required format is an array of strings for the operating system and python version inputs. This is something to capture as a future todo once arrays are available.

## Adding New Tests ##
A new smoke test should be added as a method in the [SmokeTest class](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test.py). Helper methods should be added in [smoke_test_utils.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test_utils.py).

Below is an example that tests the `scubagoggles gws` command:

```
class SmokeTest:
  ...

  def test_scubagoggles_execution(self, subjectemail):
    """
    Test if the `scubagoggles gws` command succeeds or fails.

    Args:
      subjectemail: The email address of an admin user who created the service account
    """
    try:
      command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
      result = subprocess.run(command, shell=True, check=True, capture_output=True)

      if result.returncode != 0:
        print(f"Scubagoggles execution failed with error:\n{result.stderr}")
        assert False
      else:
        print("Scubagoggles execution succeeded")
        print(f"Output:\n{result.stdout}")
    except Exception as e:
      pytest.fail(f"An error occurred, {e}")
```
