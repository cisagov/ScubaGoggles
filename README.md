
![CISA Logo](/docs/images/cisa.png)
<div align='center' style="margin:0;" id="user-content-toc">
  <ul>
    <summary><h1 style="display: inline-block;">ScubaGoggles</h1></summary>
  </ul>
  <ul>
        <a href="https://github.com/cisagov/ScubaGoggles/releases" alt="ScubaGoggles version #">
        <img src="https://img.shields.io/badge/ScubaGoggles-v0.2.0-%2385B065?labelColor=%23005288" /></a>
        <a href="https://github.com/cisagov/ScubaGoggles/tree/main/baselines" alt="GWS SCB version #">
        <img src="https://img.shields.io/badge/GWS_SCB-v0.2-%2385B065?labelColor=%23005288" /></a>
        <a href="" alt="Downloads">
        <img src="https://img.shields.io/github/downloads/cisagov/ScubaGoggles/total.svg" /></a>
  </ul>
</div>
<h2 align='center' stye="margin:0;">GWS Secure Configuration Baseline Assessment Tool </h2>

Developed by CISA, ScubaGoggles is an assessment tool that verifies a Google Workspace (GWS) organization's configuration conforms to the policies described in the Secure Cloud Business Applications ([SCuBA](https://cisa.gov/scuba)) Security Configuration Baseline [documents](https://github.com/cisagov/ScubaGoggles/tree/main/baselines).

For the Microsoft 365 (M365) rendition of this tool, see [ScubaGear](https://github.com/cisagov/ScubaGear).

> [!WARNING]
> This tool is in an alpha state and in active development. At this time, outputs could be incorrect and should be reviewed carefully.

## Overview
We use a three-step process:
1. **Export**. In this step, we primarily use the Google Admin SDK API to export and serialize all the relevant logs and settings into json. ScubaGoggles also uses various other Google APIs to grab organization metadata, user privileges etc.
2. **Verify**. Compare the exported settings from the previous step with the configuration prescribed in the baselines. We do this using [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/#what-is-rego), a declarative query language for defining policy.
3. **Report**. Package the data output by Rego into a human-friendly html report.

<!-- TODO add diagram like in ScubaGear -->

## Limitations of the tool
The majority of the conformance checks done by ScubaGoggles rely on [GWS Admin log events](https://support.google.com/a/answer/4579579?hl=en). If there is no log event corresponding to a SCuBA baseline policy, ScubaGoggles will indicate that the setting currently can not be checked on its HTML report output. In this situation, we recommend you manually review your GWS security configurations with the SCuBA security baselines. See [Limitations](/docs/usage/Limitations.md) for more details.

## Table of Contents

### Installation

- [Download and Install](/docs/installation/DownloadAndInstall.md)
- [Install OPA](/docs/installation/OPA.md)

### Prerequisites

- [Permissions](/docs/prerequisites/Permissions.md)
- [Create a Project](/docs/prerequisites/CreateAProject.md)

### Authentication

- [Using OAuth](/docs/authentication/OAuth.md)
- [Using a Service Account](/docs/authentication/ServiceAccount.md)

### Usage

- [Parameters](/docs/usage/Parameters.md)
- [Examples](/docs/usage/Examples.md)
- [Reviewing Output](/docs/usage/Output.md)
- [Limitations](/docs/usage/Limitations.md)

### Troubleshooting

- [Not Authorized to Access This Resource](/docs/usage/NotAuthorized.md)
- [scubagoggles Not Found](/docs/usage/NotFound.md)
- [Unable to view HTML report due to environment limitations](/docs/usage/CantViewHTML.md)

## Project License
Unless otherwise noted, this project is distributed under the Creative Commons Zero license. With developer approval, contributions may be submitted with an alternate compatible license. If accepted, those contributions will be listed herein with the appropriate license.
