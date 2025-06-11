# CISA Google Workspace Secure Configuration Baseline for Google Sites

Google Sites is a collaborative tool in Google Workspace that supports the creation of websites (i.e., internal project hubs, team sites, and public-facing websites) without the need of a designer, programmer, or IT help. Sites allow administrators to control and manage their files and documents. Google Drive manages sharing and publishing settings for new Sites. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Sites security.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-Federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Sites](https://support.google.com/a/topic/6385920?hl=en&ref_topic=9197) and addresses the following:

-   [Sites Service Status](#1-sites-service-status)

Google is currently transitioning from classic Sites to new Sites, [Google Workspace Admin Help: Transition from classic Sites to new Sites](https://support.google.com/a/answer/9958187?hl=en&ref_topic=25684#zippy=%2Cstarting-july-previously-january-classic-sites-transition%2Cstarting-june-previously-december-editing-of-remaining-classic-sites-will-be-disabled). Starting December 1, 2022, classic Sites will no longer be editable. And starting January 1, 2023, classic Sites will no longer be viewable unless converted to new Google Sites. All remaining classic Sites will be automatically archived as HTML files, saved to the site owner's Google Drive, and replaced with a draft in new Sites to be reviewed and published.

Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Sites Service Status

This section covers whether users are able to access Google Sites.

### Policies

#### GWS.SITES.1.1v0.5
Sites Service SHOULD be disabled for all users.

- _Rationale:_ Google Sites can increase the attack surface of Google Workspace. Disabling this feature unless it is needed conforms to the principle of least functionality.
- _Last modified:_ July 2023

- MITRE ATT&CK TTP Mapping
  - [T1526: Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Manage users' access in Sites](https://support.google.com/a/answer/6399230?hl=en)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for Site creation and editing:

#### GWS.SITES.1.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Sites**.
3.  Select **Service Status**
4.  Select **OFF for everyone**.
5.  Select **Save**.
