# CISA Google Workspace Secure Configuration Baseline for Assured Controls and Assured Controls Plus

Assured Controls and Assured Controls Plus are paid add-ons within Google Workspace relating to compliance and security.
The Secure Configuration Baseline (SCB) for Assured Controls provides specific policies to strengthen an organization's data security.
This baseline is intended as guidance for agencies that already have Assured Controls or Assured Controls Plus licenses.
Users that choose to implement this baseline should carefully consider the tradeoffs involved, including the potential security benefits, usability impacts, and increased licensing fees for the add-on licenses.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-Federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation and addresses the following:
- [Google Support Staff Data Access](#1-google-support-staff-data-access)
- [Data Regions Advanced Settings](#2-data-regions-advanced-settings)

## Assumptions

This document assumes the organization is using both GWS Enterprise Plus and the Assured Controls Plus add-on.


## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Google Support Staff Data Access

Google Workspace includes a few mechanisms to control how Google support staff access your organization's data.
Access Approvals requires Google support staff to request approval before viewing your organization's data.
Access can also be restricted to specific demographics, such as access by U.S. Google staff only.
However, these features require additional licensing and are not available by default with Enterprise Plus.

### Policy

#### GWS.ASSUREDCONTROLS.1.1v0.6
Access Approvals SHOULD be enabled.

- _Rationale:_ Unauthorized access to data increases the risk of exposing sensitive data to untrusted entities. Requiring the approval of a Google staff's request to access an organization's data may reduce unauthorized access and unauthorized actions to an organization's data.
- _Last modified:_ November 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE ATT&CK TTP Mapping
    - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
    - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
    - [T1589: Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)

#### GWS.ASSUREDCONTROLS.1.2v0.6
Agencies SHOULD restrict support access to U.S. Google staff only.

- _Rationale:_ Without this policy, data could be processed by Google personnel not physically located in the United States, potentially exposing it unauthorized entities. Implementing this policy accounts for sovereignty over organizational data.
- _Last modified:_ November 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE ATT&CK TTP Mapping
    - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
    - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
    - [T1589: Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)

### Resources

- [GWS Admin Help \| Access Approvals: Require Google staff to request approval before viewing support data](https://support.google.com/a/answer/12410469)
- [GWS Admin Help \| What data is covered by Access Management and Access Approvals?](https://support.google.com/a/answer/10379605)
- [GWS Admin Help \| Access Management: Limit Google support actions related to your data ](https://support.google.com/a/topic/10404276)
- [GWS Admin Help \| Access Management: Limit the Google staff who can take support actions related to your data ](https://support.google.com/a/answer/10343878)


### Prerequisites
- Access Approvals requires either Assured Controls or Assured Controls Plus add-ons.
- Access Management requires the Assured Controls Plus add-on. However, customers who purchased Assured Controls and the Assured Support add-on prior to June 17, 2024 also have access to Access Management.

### Implementation

#### GWS.ASSUREDCONTROLS.1.1v0.6 Instructions
1.  Sign in to the [Google Admin console](https://admin.google.com/) as a super admin.
2.  Select **Data** -\> **Compliance** -\> **Access Approvals**.
3.  Check the **Require Google staff to request approval before viewing data necessary for support services** box.
4.  Click **SAVE**.

#### GWS.ASSUREDCONTROLS.1.2v0.6 Instructions

1.  Sign in to the [Google Admin console](https://admin.google.com/) as a super admin.
2.  Select **Data** -\> **Compliance** -\> **Access Management**.
3.  Select **Access by U.S. Google Staff Only**.
4.  Click **SAVE**.

## 2. Data Regions Advanced Settings
Data regions advanced settings can be used to restrict access to features that process data globally.
However, these settings only apply to users with the Assured Controls Plus add-on.

### Policies

#### GWS.ASSUREDCONTROLS.2.1v0.6
Data processing across multiple regions SHOULD be disabled for all Google Workspace products.

-  _Rationale:_ Without this policy, data could be processed in a region other than the United States, potentially exposing it unauthorized entities. Implementing this policy accounts for sovereignty over organizational data.
- _Last modified:_ November 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)
- MITRE TTP Mapping:
    - [T1591: Gather Victim Organization Information](https://attack.mitre.org/techniques/T1591)
        - [T1591:001 Gather Victim Organization Information: Determine Physical Location](https://attack.mitre.org/techniques/T1591/001/)
    - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
    - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

### Resources
- [GWS Admin Help \| Set up advanced settings for data regions](https://support.google.com/a/answer/14310030)

### Prerequisites
- Organizations with Enterprise Plus or Data Regions add-on subscriptions are able to modify the advanced data regions settings. However, these settings only apply to users with both Enterprise Plus and Assured Controls Plus licenses.

### Implementation

#### GWS.ASSUREDCONTROLS.2.1v0.6 Instructions
1. Sign in to the [Google Admin Console](https://admin.google.com/) as an administrator.
2. Navigate to **Data** -\> **Compliance** -\> **Data Regions** -\> **Advanced Settings**.
3. Select **Calendar**, choose **Disable features that may process data across multiple regions**, then click **SAVE**.
4. Select **Drive Docs**, choose **Disable features that may process data across multiple regions**, then click **SAVE**.
5. Select **Gmail**, choose **Disable features that may process data across multiple regions**, then click **SAVE**.
6. Select **Google Chat and classic Hangouts**, choose **Disable features that may process data across multiple regions**, then click **SAVE**.
8. Select **Google Meet**, choose **Disable features that may process data across multiple regions**, then click **SAVE**.
9. Select **Gemini app and Gemini in Google Workspace apps**, choose **Disable features that may process data across multiple regions**, then click **SAVE**.
