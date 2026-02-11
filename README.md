[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cisagov/ScubaGoggles)

![ScubaGoggles Logo](https://github.com/cisagov/ScubaGoggles/raw/main/docs/images/ScubaGoggles%20GitHub%20Graphic%20v2.jpg)


[![GitHub Release][github-release-img]][release]
[![PyPI - Version][pypi-version-img]][pypi]
[![GitHub Downloads][github-downloads-img]][release]
[![PyPI Downloads][pypi-downloads-img]][pypi]
[![GitHub License][github-license-img]][license]

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
- [macOS: Certificate Verification Error](https://github.com/cisagov/ScubaGoggles/blob/rl-getopa-macos-certs/docs/troubleshooting/Troubleshooting.md#macOS-certificate-verification-error)
- [WinError 10013 Permission Error](https://github.com/cisagov/ScubaGoggles/blob/main/docs/troubleshooting/Troubleshooting.md#windows--winerror-10013-permission-error)
- [Unable to view HTML report due to environment limitations](https://github.com/cisagov/ScubaGoggles/blob/main/docs/troubleshooting/Troubleshooting.md#unable-to-view-html-report-due-to-environment-limitations)
- [ScubaGoggles lists failures for the SPF, DKIM, and DMARC policies (GWS.GMAIL.2 through GWS.GMAIL.4) even though you have published the applicable DNS records](/docs/troubleshooting/Troubleshooting.md#scubagoggles-lists-failures-for-the-spf-dkim-and-dmarc-policies-gwsgmail2-through-gwsgmail4-even-though-you-have-published-the-applicable-dns-records)

### Misc
- [Mappings](docs/misc/mappings.md)

## Project License
Unless otherwise noted, this project is distributed under the Creative
Commons Zero license. With developer approval, contributions may be
submitted with an alternate compatible license. If accepted, those
contributions will be listed herein with the appropriate license.

[release]: https://github.com/cisagov/ScubaGoggles/releases
[github-release-img]: https://img.shields.io/github/v/release/cisagov/ScubaGoggles?label=GitHub&logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/cisagov/ScubaGoggles/total?label=GitHub%20downloads
[pypi]: https://pypi.org/project/scubagoggles/
[pypi-downloads-img]: https://img.shields.io/pypi/dm/scubagoggles.svg?labelColor=%23005288&label=PyPI%20downloads
[pypi-version-img]: https://img.shields.io/pypi/v/ScubaGoggles?label=PyPI
[license]: https://github.com/cisagov/ScubaGoggles/blob/main/LICENSE
[github-license-img]: https://img.shields.io/github/license/cisagov/ScubaGoggles