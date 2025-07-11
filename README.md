![ScubaGoggles Logo](https://github.com/cisagov/ScubaGoggles/raw/main/docs/images/ScubaGoggles%20GitHub%20Graphic%20v2.jpg)
<div align='center' style="margin:0;" id="user-content-toc">
  <ul>
    <h1 style="display: inline-block;">ScubaGoggles</h1>
  </ul>
  <ul>
        <a href="https://github.com/cisagov/ScubaGoggles/releases">
        <img src="https://img.shields.io/badge/ScubaGoggles-v0.5.0-%2385B065?labelColor=%23005288"  alt="ScubaGoggles version #"></a>
        <a href="https://github.com/cisagov/ScubaGoggles/tree/main/baselines">
        <img src="https://img.shields.io/badge/GWS_SCB-v0.5-%2385B065?labelColor=%23005288" alt="GWS SCB version #"></a>
        <a href="">
        <img src="https://img.shields.io/github/downloads/cisagov/ScubaGoggles/total.svg"  alt="Downloads"></a>
  </ul>
</div>
<h2 align='center' style="margin:0;">GWS Secure Configuration Baseline Assessment Tool </h2>

Developed by CISA, ScubaGoggles is an assessment tool that verifies a Google
Workspace (GWS) organization's configuration conforms to the policies
described in the Secure Cloud Business Applications
([SCuBA](https://cisa.gov/scuba)) Secure Configuration
Baseline [documents](https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines/README.md).

For the Microsoft 365 (M365) rendition of this tool, see [ScubaGear](https://github.com/cisagov/ScubaGear).

> [!WARNING]
> This tool is in an alpha state and in active development. At this time, outputs could be incorrect and should be reviewed carefully.

## Overview
We use a three-step process:
1. **Export**. In this step, we primarily use the Google Admin SDK API to export and serialize all the relevant logs and settings into json. ScubaGoggles also uses various other Google APIs to grab organization metadata, user privileges etc.
2. **Verify**. Compare the exported settings from the previous step with the configuration prescribed in the baselines. We do this using [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/#what-is-rego), a declarative query language for defining policy.
3. **Report**. Package the results as HTML and JSON.

## Table of Contents

### Installation

- [Download and Python Install](https://github.com/cisagov/ScubaGoggles/blob/main/docs/installation/DownloadAndInstall.md)
- [Download the OPA Executable](https://github.com/cisagov/ScubaGoggles/blob/main/docs/installation/OPA.md)
- [Configure Defaults](https://github.com/cisagov/ScubaGoggles/blob/main/docs/installation/Defaults.md)

### Prerequisites

- [Permissions](https://github.com/cisagov/ScubaGoggles/blob/main/docs/prerequisites/Prerequisites.md#permissions)
- [Create a Project](https://github.com/cisagov/ScubaGoggles/blob/main/docs/prerequisites/Prerequisites.md#create-a-project)

### Authentication
- [Authentication Methods](https://github.com/cisagov/ScubaGoggles/blob/main/docs/authentication/AuthenticationMethods.md)
- [Using OAuth](https://github.com/cisagov/ScubaGoggles/blob/main/docs/authentication/OAuth.md)
- [Using a Service Account](https://github.com/cisagov/ScubaGoggles/blob/main/docs/authentication/ServiceAccount.md)

### Usage

- [Usage: Parameters](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Parameters.md)
- [Usage: Config File](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Config.md)
- [Usage: Examples](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Examples.md)
- [Reviewing Output](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/ReviewOutput.md)
- [Limitations](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Limitations.md)

### Troubleshooting
- [Not Authorized to Access This Resource](https://github.com/cisagov/ScubaGoggles/blob/main/docs/troubleshooting/Troubleshooting.md#not-authorized-to-access-this-resource)
- [WinError 10013 Permission Error](https://github.com/cisagov/ScubaGoggles/blob/main/docs/troubleshooting/Troubleshooting.md#windows--winerror-10013-permission-error)
- [Unable to view HTML report due to environment limitations](https://github.com/cisagov/ScubaGoggles/blob/main/docs/troubleshooting/Troubleshooting.md#unable-to-view-html-report-due-to-environment-limitations)

## Project License
Unless otherwise noted, this project is distributed under the Creative
Commons Zero license. With developer approval, contributions may be
submitted with an alternate compatible license. If accepted, those
contributions will be listed herein with the appropriate license.
