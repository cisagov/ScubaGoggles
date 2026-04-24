# CISA Google Workspace Secure Configuration Baseline for Google Gemini

Google Gemini is Google’s Artificial Intelligence (AI) platform to assist with several tasks in Gmail, Drive, Docs, and Meet. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Gemini security.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Gemini for Google Workspace](https://support.google.com/a/topic/13853688?hl=en&ref_topic=9197&sjid=1480967616439197109-NA) and addresses the following:

-   [Gemini App Access](#1-gemini-app-access)
-   [Alpha Gemini features](#2-alpha-gemini-features)

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST," "MUST NOT," "REQUIRED," "SHALL," "SHALL NOT," "SHOULD," "SHOULD NOT," "RECOMMENDED," "MAY," and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Automated Check**: This indicator means that the policy can be automatically checked via ScubaGoggles. See [our documentation](../../README.md) for help getting started.

**Log-Based Check**: This indicator means that ScubaGoggles will check the policy by reviewing admin audit logs. See [Limitations](../../docs/usage/Limitations.md#log-based-policy-checks).

# Baseline Policies

## 1. Gemini App Access
Data for users with a license that provides access to Gemini under the Google Workspace (GWS)
or Workspace for Education terms cannot be used by Google for training generative
AI models. However, GWS supports enabling access to Gemini, regardless
of license; only Gemini data for users with the appropriate license will be protected
by the GWS Terms of Service.

Gemini access to Google services outside of the GWS core
services can be restricted in the admin center. These additional services
are not covered by the GWS agreement and as such, could represent
some risk to user data. However, allowing Gemini access to those applications does not
increase that risk as those applications cannot access data from Gemini. See
[Additional Google Services](https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines/commoncontrols.md#16-additional-google-services)
for more details on configuring these additional services.

### Policies

#### GWS.GEMINI.1.1v0.6
Gemini app user access SHALL be set to OFF for everyone without a license.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)
[![Log-Based Check](https://img.shields.io/badge/Log--Based_Check-F6E8E5)](../../docs/usage/Limitations.md#log-based-policy-checks)

- _Rationale:_ Only Gemini data for users with the appropriate license will be
protected by the Google Workspace Terms of Service. Data for users without the
appropriate license can be used to improve Google's generative AI models. As such,
allowing user access to Gemini under any license creates the risk of data leakage.
- _Last modified:_ July 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources
-   [Turn the Gemini app on or off](https://support.google.com/a/answer/14571493)
-   [Turn Google apps in Gemini on or off](https://support.google.com/a/answer/15293691)
-   [Google Workspace Terms of Service](https://workspace.google.com/terms/premier_terms/)

### Prerequisites

-   None

### Implementation

#### GWS.GEMINI.1.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini App**.
3.  Select **User Access**.
4.  Ensure **Allow all users to access the Gemini app, regardless of license** is **Unchecked**.
5.  Select **Save**.


## 2. Gemini Alpha features
Google Workspace permits admins to restrict or enable access to Gemini Alpha features
before they're made generally available.

Note that Alpha features in Gemini are subject to the Pre-General Availability
Offering Terms (excluding Section 6.1(b)) of the Google Workspace Service
Specific Terms. Section 6.1(d) prohibits government customers from using live or
production data in connection with Pre-Gemini Alpha Offerings.

### Policies

#### GWS.GEMINI.2.1v0.6
Gemini Alpha features SHALL be disabled.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)
[![Log-Based Check](https://img.shields.io/badge/Log--Based_Check-F6E8E5)](../../docs/usage/Limitations.md#log-based-policy-checks)

- _Rationale:_ Allowing access to Gemini Alpha features may expose users to features that
have not yet been fully vetted and may still need to undergo robust testing to ensure
compliance with applicable security standards. Additionally, government customers are
prohibited from using production data with pre-general availability offerings, per the Google Workspace
Service Specific Terms.
- _Last modified:_ July 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Turn access to Google Workspace with Gemini Alpha on or off](https://support.google.com/a/answer/14170809)
-   [Google Workspace Service Specific Terms](https://workspace.google.com/terms/service-terms/index.html)

### Prerequisites

-   None

### Implementation

#### GWS.GEMINI.2.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini for Workspace.**
3.  Select **Alpha features.**
4.  Ensure **Turn off access to Alpha features in Gemini for Google Workspace** is selected.
5.  Select **Save**.

## 3. Gemini Conversation History
This section covers the Gemini conversation history retention.

### Policies

#### GWS.GEMINI.3.1v1
Gemini conversation history SHALL be enabled.

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwsgemini31v1-instructions)

- _Rationale:_ Users engaged in Gemini conversations may inadvertently share sensitive or private information. Enabling conversation history may mitigate this risk by providing a traceable record of Gemini conversations, enhancing information accountability and security. Additionally, this may help meet data retention requirements.
- _Last modified:_ March 2026
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AU-2, AU-11
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.GEMINI.3.2v1
Conversation retention SHALL be set to minimum of 18 months.

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwsgemini32v1-instructions)

- _Rationale:_ Users engaged in Gemini conversations may inadvertently share sensitive or private information. Enabling conversation history may mitigate this risk by providing a traceable record of Gemini conversations, enhancing information accountability and security. Additionally, this may help meet data retention requirements.
- _Last modified:_ March 2026
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AU-2, AU-11
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Manage Gemini in Workspace conversation history settings](https://knowledge.workspace.google.com/admin/gemini/manage-gemini-in-workspace-conversation-history-settings)

### Prerequisites

-   None

### Implementation

#### GWS.GEMINI.3.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini App**.
3.  Select **Gemini Conversation History**
4.  Ensure **Gemini conversation history** is selected.
5.  Select **Save**.

#### GWS.GEMINI.3.2v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini App**.
3.  Select **Gemini Conversation History**
4.  Ensure **Conversation retention** is set to at least 18 months.
5.  Select **Save**.

## 4. Gemini Conversation Sharing
This section covers the Gemini conversation sharing.

### Policies

#### GWS.GEMINI.4.1v1
Conversation sharing SHALL be set to OFF.

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwsgemini31v1-instructions)

- _Rationale:_ Users engaged in Gemini conversations may inadvertently share sensitive or private information. Disabling conversation sharing may prevent sensitive data from being shared with unauthorized individuals.
- _Last modified:_ April 2026
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AU-2, AU-11
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Turn conversation sharing on or off](https://knowledge.workspace.google.com/admin/gemini/turn-conversation-sharing-on-or-off)

### Prerequisites

-   None

### Implementation

#### GWS.GEMINI.4.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini App**.
3.  Select **Sharing**
4.  Ensure **Allow conversation sharing via link** is set to OFF.
5.  Select **Save**.

