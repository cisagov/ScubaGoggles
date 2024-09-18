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

## Functional Smoke Testing Structure ##
ScubaGoggles functional smoke testing has two main components: the smoke testing orchestrator and the automated workflow which is run via GitHub Actions.

### Smoke testing orchestrator ### 
The smoke testing orchestrator ([/Testing/Functional/SmokeTests/smoke_test.py](https://github.com/cisagov/ScubaGoggles/blob/main/Testing/Functional/SmokeTests/smoke_test.py)) executes each test declared inside the `SmokeTest` class. The tests currently cover:
- if the `scubagoggles gws` command generates correct output for all baselines
- if ScubaResults.json contains API errors or exceptions
-  if the generated baseline reports are correct, i.e. BaselineReports.html, CalendarReport.html, ChatReport.html

### Automated workflow via GitHub Actions ### 
