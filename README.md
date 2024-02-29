<div align='center' style="margin:0;" id="user-content-toc">
  <ul>
    <summary><h1 style="display: inline-block;">ScubaGoggles</h1></summary>
  </ul>
  <ul>
        <a href="https://github.com/cisagov/ScubaGoggles/releases" alt="ScubaGoggles version #">
        <img src="https://img.shields.io/badge/ScubaGoggles-v0.1.0-%2385B065?labelColor=%23005288" /></a>
        <a href="https://github.com/cisagov/ScubaGoggles/tree/main/baselines" alt="GWS SCB version #">
        <img src="https://img.shields.io/badge/GWS_SCB-v0.1-%2385B065?labelColor=%23005288" /></a>
        <a href="" alt="Downloads">
        <img src="https://img.shields.io/github/downloads/cisagov/ScubaGoggles/total.svg" /></a>
  </ul>
</div>
<h2 align='center' stye="margin:0;">GWS Secure Configuration Baseline Assessment Tool </h2>

Developed by CISA, ScubaGoggles is an assessment tool that verifies a Google Workspace (GWS) organization's configuration conforms to the policies described in the Secure Cloud Business Applications ([SCuBA](https://cisa.gov/scuba)) Security Configuration Baseline [documents](https://github.com/cisagov/ScubaGoggles/tree/main/baselines).

For the Microsoft 365 (M365) rendition of this tool, see [ScubaGear](https://github.com/cisagov/ScubaGear).

> [!WARNING]
> This tool is in an alpha state and in active development. At this time, outputs could be incorrect and should be reviewed carefully.

## Table of Contents
- [Limitations of the tool](#limitations-of-the-tool)
- [Getting Started](#getting-started)
  - [Downloading the Latest Release](#downloading-the-latest-release)
  - [Python Dependencies](#install-python-dependencies)
  - [Installing in a Virtual Environment](#installing-in-a-virtual-environment)
  - [Downloading the OPA executable](#download-the-opa-executable)
  - [Permissions](#permissions)
  - [Create a Project](#create-a-project)
  - [Authentication](#authentication)
- [Usage](#usage)
  - [Examples](#example-1-run-an-assessment-against-all-gws-products)
- [Organization](#organization)
- [Design](#project-license)
- [Troubleshooting](#troubleshooting)
  - [Not Authorized to Access this Resource](#not-authorized-to-access-this-resource)
  - [ScubaGoggles not Found](#scubagoggles-not-found)
  - [Unable to view HTML report due to environment limitations](#Unable-to-view-HTML-report-due-to-environment-limitations)
- [Project License](#project-license)

## Limitations of the tool
The majority of the conformance checks done by ScubaGoggles rely on [GWS Admin log events](https://support.google.com/a/answer/4579579?hl=en). If there is no log event corresponding to a SCuBA baseline policy, ScubaGoggles will indicate that the setting currently can not be checked on its HTML report output. In this situation, we recommend you manually review your GWS security configurations with the SCuBA security baselines.

Additionally, some events will not be visible due to data retention time limits, as the admin logs are only retained for 6 months (see [Data retention and lag times](https://support.google.com/a/answer/7061566)). However, if you wish to generate a log event for testing ScubaGoggles' capabilities, follow the implementation instructions in the [SCuBA GWS baseline documents](https://github.com/cisagov/ScubaGoggles/tree/main/baselines) to change your GWS configuration settings. Toggling certain settings, off and on will be enough to generate a log event. Other settings will require implementing more substantive configuration changes.

Many of the these controls can be scoped down to the organizational unit level. We recommend [creating a new organization unit](https://support.google.com/a/answer/182537?hl=en#:~:text=An%20organizational%20unit%20is%20simply,level%20(parent)%20organizational%20unit) and applying these controls just to that new organizational unit for testing. Rerun ScubaGoggles after you've saved your configuration changes to see if the policy requirement is met.

## Getting started

> [!IMPORTANT]
> Use of this tool requires access to an internet browser for initial setup and to view the html report output.

### Downloading the Latest Release
To download ScubaGoggles:

1. Click [here](https://github.com/cisagov/ScubaGoggles/releases) to see the latest release.
2. Click scubagoggles-[latest-version].zip to download the release.
3. Extract the folder in the zip file.

### Install Python dependencies
Minimum required Python version to run the tool is `3.7.16`.

### Installing in a Virtual Environment
The following commands are used to set up a python virtual environment (venv) to install the needed python dependencies.
Inside the release or repo folder, open up a terminal and run the following commands based on your OS.

#### Windows
```
pip3 install virtualenv
python -m venv .venv
.venv\Scripts\activate
```

#### macOS
```
pip3 install virtualenv
virtualenv -p python3 .venv
source .venv/bin/activate
```

Users can run the tool via the `scuba.py` script as a developer or by installing the `scubagoggles` package in a python venv.
Choose either of these next steps to install the needed python dependencies in the `venv`.

#### Installing dependencies for running scubagoggles directly
In the root directory of the release/repo, install the `scubagoggles` package and dependencies with the following command.
```
python3 -m pip install .
```

#### Installing dependencies for running via scuba.py script
In the root directory of the release/repo, install the the required dependencies with the following command.
```
pip3 install -r requirements.txt
```

> [!IMPORTANT]
> Users will need to rerun the `activate` script from the OS specific directions above in each new terminal session to reactivate the `venv` containing the dependencies.

### Download the OPA executable

The tool makes use of [Open Policy Agent's Rego Policy language](https://www.openpolicyagent.org/docs/latest/policy-language/).
An OPA executable is required to execute this tool and can be downloaded using our `download_opa.py` script.

```
python download_opa.py --help
usage: download_opa.py [-h] [-v] [-os]

Download executable the OPA executable file required to run this SCuBA tool.

options:
  -h, --help            show this help message and exit
  -v {0.45.0,0.46.3,0.47.4,0.48.0,0.49.2,0.50.2,0.51.0,0.52.0,0.53.1,0.54.0,0.55.0,0.56.0,0.57.1,0.58.0,0.59.0,0.60.0}
                        What version of OPA to download: Default version: 0.59.0
  -os {windows,macos,linux}
                        Operating system version of OPA to download. Default os: windows
  --disablessl          If there are proxy errors, try adding this switch to disable ssl verification
```
```
# example
python download_opa.py -v 0.60.0 -os macos
```
1. If the above script can not execute for any reason or you would prefer to download OPA manually, go to the [Open Policy Agent website](https://www.openpolicyagent.org/docs/latest/#running-opa)
2. Check the website for a compatible OPA version (Currently v0.45.0 and above) for ScubaGoggles and select the corresponding version on top left of the website
3. Navigate to the menu on left side of the screen: `Introduction -> Running OPA -> Download OPA`
4. Follow the instructions for downloading the respective OPA executable for your OS.

> [!NOTE]
> The following notes apply only for MAC and Linux users.
- By default on MAC and Linux systems the OPA executable will be run with `sudo`.
- Use the `scubagoggles gws --omitsudo` flag to omit running the executable with `sudo`.
- MAC and Linux OS users should have their OPA executables named `opa_darwin_amd64` or `opa_linux_amd64_static` respectively for scubagoggles execution.
- The OPA executable must also be given execute permissions
```bash
chmod +x opa_darwin_amd64 # give the opa executable execute permissions
```

### Permissions

#### OAuth API Scopes
The tool uses the following OAUTH API scopes.
- `https://www.googleapis.com/auth/admin.reports.audit.readonly`
- `https://www.googleapis.com/auth/admin.directory.domain.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
- `https://www.googleapis.com/auth/admin.directory.orgunit.readonly`
- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/apps.groups.settings`

When running ScubaGoggles for the first time you will be prompted to consent to these API scopes. Users with the Super Admin role automatically have the privilege to consent to these scopes. A custom admin role can also be made with the minimum permissions to consent to these scopes. See this [Google Admin SDK Prerequisites guide](https://developers.google.com/admin-sdk/reports/v1/guides/prerequisites) for more information.

### Create a project
1. If you already have a Google Cloud Project that you want to utilize skip to [Authentication](#authentication)
2. Otherwise start by signing into http://console.cloud.google.com/.
3. Follow the [directions outlined in this guide to create a project](https://developers.google.com/workspace/guides/create-project)

### Authentication

ScubaGoggles supports both OAuth and Service Accounts for authorization/authentication.
OAuth requires regular user consent while using a service account allows for more automation.
Follow the instructions below for the authentication method of your choice.


#### Create an OAuth credential
1. Be signed into http://console.cloud.google.com/.
1. From the hamburger menu on the left, select **APIs & Services** -> **OAuth consent screen**
1. Select **Internal** for **User Type**
1. Click **Create**
1. Fill in your **App name** and **User support email**
1. Scroll down to the **Authorized Domains** section
1. Under **Authorized domains**, add the primary domain of your GWS organization.
1. Add another email address for **Developer contact information**
1. Click **SAVE AND CONTINUE**
1. Do nothing on the **Scopes** screen, just click **SAVE AND CONTINUE**
1. Review summary, then click **BACK TO DASHBOARD**
1. Click **Credentials** from the menu on the left
1. Click **CREATE CREDENTIALS**
1. Select **Oauth client ID**
1. Select **Web application** for **Application type**
1. Give name as appropriate
1. Under **Authorized redirect URIs**, click "ADD URI." Add `http://localhost` and `http://localhost:8080/`
1. Click **CREATE**
1. Click **DOWNLOAD JSON** from the resulting **OAuth client created** page
1. Click **OK**
1. Move the downloaded file (begins with `client_secret*.json`) to the root directory folder of this repo, rename to `credentials.json`
1. Go back the menu on the left and click **Enabled API Services**
1. In the center screen click **Enable APIS AND Services**
1. Search for and enable the **Admin SDK API**
1. Search for and enable the **Groups Settings API**
1. During the first run of this tool your default web browser will open up a page to consent to the API scopes needed to run this tool. Sign in
with an account with the necessary privileges and click allow.

##### Add the Oauth App to the allowlist
If you've limited application access to Google's APIs in your organization, the [Common Controls: App Access to Google APIs](https://github.com/cisagov/ScubaGoggles/blob/main/baselines/Common%20Controls%20Minimum%20Viable%20Secure%20Configuration%20Baseline%20v0.1.md#11-app-access-to-google-apis) baseline covers this topic, follow the directions below to allowlist the OAuth app.

1. Login to https://console.cloud.google.com
1. Navigate to the appropriate project
1. Select **API's & Services** from the top left hamburger icon
1. Select **Credentials**
1. Copy your client ID under **OAuth 2.0 Client IDs**
1. Now login to [admin.google.com](https://admin.google.com/) and navigate to **Security** -> **Access and Data Control** -> **API Controls** -> **Manage Third-Party App Access**
1. Select **Add App** -> **Oauth App Name** or **Client ID**
1. Search by your **OAuth client ID**
1. Select the App
1. Select your root organization as the domain
1. Select **Trusted**

#### Using a Service Account

> [!Important]
> ScubaGoggles requires the service account to have [domain-wide delegation of authority](https://support.google.com/a/answer/162106?hl=en) to function. 

1. Login to https://console.cloud.google.com and navigate to your GCP project.
1. From the hamburger menu, select **IAM & Admin** -> **Service Accounts**
1. Select **CREATE SERVICE ACCOUNT**. Fill out the id field and then select **DONE**
1. Click on the newly created service account then click **KEYS** -> **ADD KEY** -> **Create new key** -> **JSON** -> **CREATE**
1. Move the downloaded file (begins with `<service account>*.json`) to the root directory folder of this repo, rename to `credentials.json`
1. Now login to [admin.google.com](https://admin.google.com/) and navigate to **Security** -> **Access and data control** -> **API controls**
1. Select **MANAGE DOMAIN WIDE DELEGATION**
1. Select **Add new**
1. Enter the `client_id` from the downloaded credentials (also visible after clicking on the created Service account under Details -> Unique ID)
1. Enter each OAuth scope as listed in [OAuth API Scopes](#oauth-api-scopes)
1. Select **AUTHORIZE**
1. Finally, run ScubaGoggles with the `--subjectemail` option set to the email of an admin with necessary permissions to run ScubaGoggles.

> [!NOTE] 
> ScubaGoggles can be run using a service account in a different organization. 
> To do so, specify the `--customerid` argument with the customer ID of the target organization (found in [admin.google.com](https://admin.google.com/) under **Account** -> **Account settings**) 

## Usage
Execute the ScubaGoggles tool using the `scubagoggles` command. For GWS, all commands will be under the `gws` subparser.

```
scubagoggles gws -h
usage: scubagoggles gws [-h] [-b  [...]] [-o] [-c] [--subjectemail] [--customerid] [--opapath] [--regopath] [--documentpath]
                    [--runcached] [--skipexport] [--outputfoldername] [--outputproviderfilename]
                    [--outputregofilename] [--outputreportfilename] [--omitsudo] [--quiet] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -b  [ ...], --baselines  [ ...]
                        A list of one or more abbreviated GWS baseline names that the tool will assess. Defaults to
                        all baselines. Choices: gmail, calendar, groups, chat, drive, meet, sites, commoncontrols,
                        rules, classroom
  -o , --outputpath     The folder path where both the output JSON & HTML report will be created. Defaults to "./" The
                        current directory.
  -c , --credentials    The relative path and name of the OAuth / service account credentials json file. Defaults to
                        "./credentials.json" which means the tool will look for the file named credentials.json in the
                        current directory.
  --subjectemail        Only applicable when using a service account. The email address of a user the service account
                        should act on behalf of. This user must have the necessary privileges to run scubagoggles.
  --customerid          The customer ID the tool should run on. Defaults to "my_customer" which will be the domain of 
                        the user / service account authenticating.
  --opapath             The relative path to the directory containing the OPA executable. Defaults to "./" the current
                        executing directory.
  --regopath            The relative path to the directory contain the folder containing the rego files. Defaults to
                        "./rego" the "rego" folder inside the current executing directory.
  --documentpath        The relative path to the directory containing the SCuBA baseline documents. Defaults to
                        "./baselines" the "baselines" folder inside the current executing directory.
  --runcached           This switch when added will run in the tool in "RunCached mode". When combined with -sa allows
                        to the user to skip authentication and provider export.
  --skipexport          This switch when added will skip the provider export.To be used in conjunction with
                        --runcached.
  --outputfoldername    The name of the folder created in --outputpath where both the output JSON and the HTML report
                        will be created. Defaults to GWSBaselineConformance. The client's local timestamp will be
                        appended to this name.
  --outputproviderfilename 
                        The name of the Provider output json in --outputpath. Defaults to ProviderSettingsExport.
  --outputregofilename 
                        The name of the Rego output json in --outputpath. Defaults to TestResults.
  --outputreportfilename 
                        The name of the main html file homepage created in --outputpath. Defaults to BaselineReports.
  --omitsudo            This switch prevents running the OPA executable with sudo.
  --quiet               This switch suppresses automatically launching a web browser to open the html report output
                        and the loading bar output.
  --debug               This switch is used to print debugging information for OPA.
```

### Example 1: Run an assessment against all GWS products
```
scubagoggles gws
```

### Example 2: Run an assessment against just Gmail and Google Calendar
```
scubagoggles gws -b gmail calendar
```

### Example 3: Run an assessment and store the results under a folder called output
```
scubagoggles gws -b calendar gmail groups chat meet sites -o ./output
```

### Example 4: Do a run cached assessment
```
# skip authentication and provider export stage
# used for running against a cached provider json

scubagoggles gws --runcached --skipexport
```

### Example 5: Run with a service account on a different tenant
```
scubagoggles gws --customerid <customer_id> --subjectemail admin@example.com
```

See the `help` options yourself
```
scubagoggles gws -h
```

The html report should open automatically. If not, navigate to the output folder and open the `*.html` file using a browser of your choice. The json output will also be located in this folder.

> [!NOTE]
> If you chose not install the `scubagoggles` package in a venv but do have the dependencies installed from `requirements.txt`, you may execute the tool using the `scuba.py` script located in the root directory of this repository. Replace any `scubagoggles` directions with `python scuba.py`

## Organization
- The Python scripts are saved in the `scubagoggles` folder.
- The `rego` folder holds the Rego files. Each `*.rego` file holds the "desired state" for each product, per the baseline policy statements.
- Style and developer guides are located in the `guides` folder.

## Design
We use a three-step process:
1. **Export**. In this step, we primarily use the Google Admin SDK API to export and serialize all the relevant logs and settings into json. ScubaGoggles also uses various other Google APIs to grab organization metadata, user privileges etc.
2. **Verify**. Compare the exported settings from the previous step with the configuration prescribed in the baselines. We do this using [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/#what-is-rego), a declarative query language for defining policy.
3. **Report**. Package the data output by Rego into a human-friendly html report.

## Troubleshooting
### Not Authorized to Access This Resource

If an authorization error similar to the one below appears:
```
/Users/scubagoggles/provider.py:463: RuntimeWarning: An exception was thrown trying to get the tenant info:
<HttpError 403 when requesting https://admin.googleapis.com/admin/directory/v1/customers/my_customer?alt=json returned "Not Authorized to access this resource/api">
```
Ensure that you consented to the following API scopes as a user with the proper [permissions to consent](#permissions) and have enabled the required [APIs and Services](#create-an-oauth-credential).

### Scubagoggles Not Found 
If an error similar to the one below appears: 
```
command not found: scubagoggles
```

Ensure that you have properly [configured the virtual environment](#installing-in-a-virtual-environment) and have activated the virtual environment using the OS appropriate commands. 

Alternatively, to run scubagoggles without installing it as a package, you can replace the `scubagoggles` command with `python scuba.py`. 

### Unable to view HTML report due to environment limitations 

If you are unable to view the HTML report in a browser window, the results of the conformance scan can be viewed in their raw JSON format. 

We recommend running the conformance report in quiet mode to stop the web browser from being opened automatically. This can be done with the `--quiet` command: 

```scubagoggles gws --quiet```

Once the scan is complete, navigate to the output folder. Within the output folder, we can access the generated HTML reports, or view the results in JSON format. 

To view the JSON, open the `TestResults.json` file. 

Each baseline will appear in the following format: 

```
    {
        "ActualValue": {
            "NonCompliantOUs": []
        },
        "Criticality": "Shall",
        "NoSuchEvent": false,
        "PolicyId": "GWS.CHAT.5.1v0.1",
        "ReportDetails": "Requirement met in all OUs.",
        "RequirementMet": true
    },

```
The `RequirementMet` field indicates whether the baseline associated with the given PolicyId is compliant or not. 


## Project License
Unless otherwise noted, this project is distributed under the Creative Commons Zero license. With developer approval, contributions may be submitted with an alternate compatible license. If accepted, those contributions will be listed herein with the appropriate license.
