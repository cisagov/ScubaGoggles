# ScubaGoggles Functional Smoke Testing Automation
The ScubaGoggles repository consists of an automation suite to help test the functionality of the ScubaGoggles tool itself. The test automation is geared towards contributors who want to execute the functional smoke testing orchestrator as part of their development/testing activity.

This README outlines the ScubaGoggles software test automation and its usage. The document also contains instructions for adding new functional tests to existing automation suite.

## Table of Contents 

## Smoke Testing Prerequisites ## 
Running the ScubaGoggles functional smoke tests requires a Windows, MacOS, or Linux computer or VM. The development environment should have Python v3.10.x installed at a minimum ([refer to our installing Python dependencies documentation if its not already installed](https://github.com/cisagov/ScubaGoggles/blob/main/docs/installation/DownloadAndInstall.md#installing-python-dependencies)), Pytest, and Selenium installed locally.

### Pytest and Selenium ### 
Pytest is a Python testing framework which is commonly used for unit, integration, and functional testing. [Pytest Get Started](https://docs.pytest.org/en/stable/getting-started.html)

Selenium supports automation of all the major browsers in the market through the use of WebDriver. [Selenium Get Started](https://www.selenium.dev/documentation/webdriver/getting_started/)

To install Pytest and Selenium on your development environment, open a new terminal session and run the following command:

```
pip install pytest selenium
```

> [!NOTE]
> The functional smoke tests use Chrome as its WebDriver when running Selenium tests. If you don't already have the Google Chrome web browser installed, [setup ChromeDriver here](https://developer.chrome.com/docs/chromedriver/get-started).

### Google Service Account ###
The ScubaGoggles functional smoke tests must be executed with a service account. [Refer to our documentation here on how to get setup.](https://github.com/cisagov/ScubaGoggles/blob/main/docs/authentication/ServiceAccount.md#using-a-service-account)

A `credentials.json` file is required at the root directory of the ScubaGoggles project if running the functional smoke tests in a local development environment.

Take note of the `subjectemail`, the email used to authenticate with GWS that has necessary administrator permissions, and the GWS `customerdomain` that ScubaGoggles is run against. Both credentials are required in a later step.

## Functional Smoke Testing Structure ##
ScubaGoggles functional smoke testing has two main components: the smoke testing orchestrator and the automated workflow which is run via GitHub Actions.

### Smoke testing directory structure ### 
The smoke testing orchestrator ([/Testing/Functional/SmokeTests/smoke_test.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test.py)) executes each test declared inside the `SmokeTest` class. The tests currently cover:
- if the `scubagoggles gws` command generates correct output for all baselines
- if ScubaResults.json contains API errors or exceptions
-  if the generated baseline reports are correct, i.e. BaselineReports.html, CalendarReport.html, ChatReport.html

The smoke testing utils ([/Testing/Functional/SmokeTests/smoke_test_utils.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test_utils.py)) stores helper methods which perform various operations.

The Selenium Browser class ([/Testing/Functional/SmokeTests/selenium_browser.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/selenium_browser.py)) encapsulates the setup, usage, and teardown of Selenium WebDriver instances.

The Pytest configuration methods ([/Testing/Functional/SmokeTests/conftest.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/conftest.py)) declare various Pytest fixtures, allowing for the use of CLI arguments when invoking the Pytest command.  

### Automated workflow via GitHub Actions ### 
The automated workflow for running the functional smoke tests ([/.github/workflows/run_smoke_test.yml](https://github.com/cisagov/ScubaGoggles/blob/main/.github/workflows/run_smoke_test.yml)) is triggered on `push` events to the main branch, `pull_request` events when a pull request is opened/reopened, and manually with customer user input via workflow_dispatch.

## Functional Smoke Testing Usage ## 
After completing all of the prerequisite steps, the functional smoke tests can be run on a local development environment or remotely via GitHub Actions.

### Running on a local development environment ### 
Ensure that you have correctly setup a Google service account and that the `credentials.json` stored at the root directory of the ScubaGoggles project is up to date. If you haven't already, please refer back to the [prerequisite step](/Google-Service-Account) on how to get setup before proceeding. 

The following arguments are required when running the functional smoke tests:
- `subjectemail`: user@domain.com (the email used to authenticate with GWS, must have necessary administrator permissions)
- `customerdomain`: domain.com (the domain that ScubaGoggles is run against)

Run the following command to execute the functional smoke tests:
```
pytest -vvv ./Testing/Functional/SmokeTests/ --subjectemail="user@domain.com" --customerdomain="domain.com"
```

Common Pytest parameters and their use cases:
- `-v` or `--verbose` (shows individual test names and results)
- `-vv` (increases verbosity further, shows detailed output about each test)
- `-vvv` (shows even more detailed output and debug-level information)
- `-s` (disables output capturing allowing print() statements and logs to be shown in the console)

### Running remotely via GitHub Actions ### 

