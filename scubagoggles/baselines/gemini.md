# CISA Google Workspace Secure Configuration Baseline for Google Gemini

Google Gemini is Google’s AI platform to assist with several tasks in Gmail, Drive, Docs, and Meet. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Gemini security.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-Federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Gemini for Google Workspace](https://support.google.com/a/topic/13853688?hl=en&ref_topic=9197&sjid=1480967616439197109-NA) and addresses the following:

-   [Gemini App Access](#1-gemini-app-access)
-   [Alpha Gemini features](#2-alpha-gemini-features)

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Gemini App Access
In General, user Gemini data for Workspace users is protected by the Google Workspace Terms of Service.
However, there are a few exceptions to this that necessitate restricting Gemini access in some cases,
detailed in the following policies.

### Policies

#### GWS.GEMINI.1.1v0.5
Gemini app user access SHALL be set to OFF for everyone without a license.

- _Rationale:_ While Google Workspace supports allowing users to access Gemini regardless of license,
only the data for users with the appropriate license will be protected by the Google Workspace Terms of Service.
Data for users without the appropriate license can be used to improve generative AI models; as such,
allowing user access to Gemini under any license creates the risk of data leakage.
- _Last modified:_ July 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.GEMINI.1.2v0.5
Gemini access to other Google apps SHALL be disabled.


- _Rationale:_ Allowing Gemini access to other Google apps increases the risk of data leakage as
the data for additional services are not covered by the organization's Google Workspace agreement.
- _Last modified:_ July 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources
-   [Turn the Gemini app on or off](https://support.google.com/a/answer/14571493)
-   [Google Workspace Terms of Service](https://workspace.google.com/terms/premier_terms/)
-   [Turn Google apps in Gemini on or off](https://support.google.com/a/answer/15293691)

### Prerequisites

-   None

### Implementation

#### GWS.GEMINI.1.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini App**.
3.  Select **User Access**.
4.  Ensure **Allow all users to access the Gemini app, regardless of license** is **Unchecked**.
5.  Select **Save**.

#### GWS.GEMINI.1.2v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini App**.
3.  Select **Apps**.
4.  Select **Other Google apps**.
4.  Ensure **Allow access to other Google apps** is **Unchecked**.
5.  Select **Save**.


## 2. Alpha Gemini features
Google Workspace permits admins to enable access to Gemini Alpha features before
they're made generally available.

Note that Alpha features in Gemini are subject to the Pre-General Availability
Offering Terms (excluding Section 6.1(b)) of the Google Workspace Service
Specific Terms. Section 6.1(d) prohibits government customers from using live or
production data in connection with Pre-GA Offerings.

### Policies

#### GWS.GEMINI.2.1v0.5
Alpha Gemini features SHALL be disabled.

- _Rationale:_ Allowing access to alpha features may expose users to features that
have not yet been fully vetted and may still need to undergo robust testing to ensure
compliance with applicable security standards.
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

#### GWS.GEMINI.2.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Generative AI** -\> **Gemini for Workspace**.
3.  Select **Alpha Gemini features**.
4.  Ensure **Turn off access to Alpha features in Gemini for Google Workspace** is selected.
5.  Select **Save**.
