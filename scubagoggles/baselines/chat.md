# CISA Google Workspace Secure Configuration Baseline for Google Chat

Google Chat is a communication and collaboration tool in Google Workspace (GWS) that supports direct messaging, group conversations, content creation, and sharing. Chat allows administrators to control and manage their messages and files. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Chat security.

The Cybersecurity and Infrastructure Security Agency's (CISA) Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the federal government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products. CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Google Chat settings](https://support.google.com/a/answer/9540647?hl=en) and addresses the following:

-   [Chat History](#1-chat-history)
-   [External File Sharing](#2-external-file-sharing)
-   [History for Spaces](#3-history-for-spaces)
-   [External Chat Messaging](#4-external-chat-messaging)
-   [Content Reporting](#5-content-reporting)

Settings can be assigned to certain GWS users individually, through organizational units, or through configuration groups. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST," "MUST NOT," "REQUIRED," "SHALL," "SHALL NOT," "SHOULD," "SHOULD NOT," "RECOMMENDED," "MAY," and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

[![BOD 25-01 Requirement](https://img.shields.io/badge/BOD_25--01_Requirement-C41230)](https://www.cisa.gov/news-events/directives/bod-25-01-implementation-guidance-implementing-secure-practices-cloud-services) (**BOD 25-01 Requirement**): This indicator means that the policy is required under CISA BOD 25-01.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology) (**Automated Check**): This indicator means that the policy can be automatically checked via ScubaGoggles. See [our documentation](../../README.md) for help getting started.

[![Configurable](https://img.shields.io/badge/Configurable-005288)](../../docs/usage/Config.md#break-glass-accounts)(**Configurable**): This indicator means that the policy can be customized via a configuration file.

[![Log-Based Check](https://img.shields.io/badge/Log--Based_Check-F6E8E5)](../../docs/usage/Limitations.md#log-based-policy-checks)(**Log-Based Check**): This indicator means that ScubaGoggles will check the policy by reviewing admin audit logs. See [Limitations](../../docs/usage/Limitations.md#log-based-policy-checks).

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwscommoncontrols83v06-instructions)(**Manual**): This indicator means that the policy requires manual verification of configuration settings.

# Baseline Policies

## 1. Chat History

This section covers chat history retention for users within the organization and prevents users from changing their history setting. This control applies to both direct messages and group messages.

### Policies

#### GWS.CHAT.1.1v1
Chat history SHALL be enabled for information traceability.

[![BOD 25-01 Requirement](https://img.shields.io/badge/BOD_25--01_Requirement-C41230)](https://www.cisa.gov/news-events/directives/bod-25-01-implementation-guidance-implementing-secure-practices-cloud-services)
[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Google Chat users may inadvertently share sensitive or private information during conversations. Preservation of chat history may be crucial if details discussed in chats are needed for future reference or dispute resolution. Enabling chat history for Google Chat may mitigate these risks by providing a traceable record of all conversations, enhancing information traceability and security.
- _Last modified:_ July 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AU-2, SC-7(10)
- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

#### GWS.CHAT.1.2v1
Users SHALL NOT be allowed to change their history setting.

[![BOD 25-01 Requirement](https://img.shields.io/badge/BOD_25--01_Requirement-C41230)](https://www.cisa.gov/news-events/directives/bod-25-01-implementation-guidance-implementing-secure-practices-cloud-services)
[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Altering the Google Chat history settings can potentially allow users to obfuscate the sharing of sensitive information via Chat. This policy helps preserve all Google Chat histories, enhancing data security and promoting accountability among users.
- _Last modified:_ July 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AU-9
- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

### Resources

-   [Google Workspace Admin Help: Turn chat history on or off for users](https://support.google.com/a/answer/7664184)

### Prerequisites

-   None

### Implementation

To configure the settings for Google Chat history:

#### GWS.CHAT.1.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **History for chats**.
4.  Select **History is ON**.
5.  Select **Save**

#### GWS.CHAT.1.2v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **History for chats**.
4.  Uncheck the **Allow users to change their history setting** checkbox.
5.  Select **Save**.

## 2. External File Sharing

This section covers sharing files externally through Google Chat.

### Policies

#### GWS.CHAT.2.1v1
External file sharing SHALL be disabled to protect sensitive information from unauthorized or accidental sharing.

[![BOD 25-01 Requirement](https://img.shields.io/badge/BOD_25--01_Requirement-C41230)](https://www.cisa.gov/news-events/directives/bod-25-01-implementation-guidance-implementing-secure-practices-cloud-services)
[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Enabling external file sharing in Google Chat opens an avenue for data loss that may not be as rigorously monitored or protected as traditional collaboration channels, such as email. This policy limits the potential for unauthorized or accidental sharing.
- _Last modified:_ July 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AC-3, SC-7(10)
- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources

-   [Google Workspace Admin Help: Control file sharing in Chat](https://support.google.com/a/answer/10277783?hl=en)

### Prerequisites

-   None

### Implementation

To configure the settings for external file sharing:

#### GWS.CHAT.2.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **Chat file sharing**.
4.  In the **External file sharing** dropdown menu, select **No files.**
5.  Select **Save**.

## 3. History for Spaces

This section covers whether chat history is retained by default for users within the organization. This control does not apply for threaded chat spaces because those require that "history" be turned on, a setting that cannot be changed. Chat spaces allow multiple users to share files, assign tasks, and stay connected.

### Policies

#### GWS.CHAT.3.1v1
Space history SHOULD be enabled for information traceability.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Google Chat users may inadvertently share sensitive or private information during conversations. Preservation of chat history may be crucial if details discussed in chats are needed for future reference or dispute resolution. Enabling chat history for Google Chat may mitigate these risks by providing a traceable record of all conversations, enhancing information traceability and security.
- _Last modified:_ July 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AU-2, SC-7(10)
- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

### Resources

-   [Google Workspace Admin Help: Set a space history option for users](https://support.google.com/a/answer/9948515?hl=en)

### Prerequisites

-   None

### Implementation

To configure the settings for history for spaces:

#### GWS.CHAT.3.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **History for spaces**.
4.  Select **History is always on**.
5.  Select **Save**.

## 4. External Chat Messaging

This section permits users to send Google Chat messages outside of their organization but requires that external Google Chat messages must be restricted to allowlisted domains only.

### Policies

#### GWS.CHAT.4.1v1
External chat messaging SHALL be restricted to allowlisted domains only.

[![BOD 25-01 Requirement](https://img.shields.io/badge/BOD_25--01_Requirement-C41230)](https://www.cisa.gov/news-events/directives/bod-25-01-implementation-guidance-implementing-secure-practices-cloud-services)
[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Allowing Google Chat external chat messaging to unrestricted domains opens additional avenues for data exfiltration, increasing the risk of data leakage. Restricting external chat messaging to only allowlisted domains helps minimize the risk of sensitive information being shared outside the organization without explicit consent and approval.
- _Last modified:_ November 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AC-3
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1213.005: Data from Information Repositories: Messaging Applications](https://attack.mitre.org/techniques/T1213/005/)

### Resources

-   [Google Workspace Admin Help: Set external chat options](https://support.google.com/a/answer/9269229?product_name=UnuFlow&visit_id=637841711304802210-4105703050&rd=1&src=supportwidget0)
-   [Google Workspace Admin Help: Allow external sharing with only trusted domains](https://support.google.com/a/answer/6160020)
-   [CIS Google Workspace Benchmark v1.1.0 - 3.1.4.2.2 Ensure Google Chat Externally is Restricted to Allowlisted Domains](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for external chats:

#### GWS.CHAT.4.1v1 Instructions
To enable external chat for allowlisted domains only:
1. Sign in to the [Google Admin Console](https://admin.google.com).
2. Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3. Select **External chat settings** -\> **Chat externally**.
4. Select **ON**.
5. Select **Only allow this for allowlisted domains**.
6. To add allowlisted domains select **Manage allowlisted domains**.
7. Select **Save**.

Alternatively, to disable external chat entirely:
1. Sign in to the [Google Admin Console](https://admin.google.com).
2. Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3. Select **External chat settings** -\> **Chat externally**.
4. Select **off**
5. Select **Save**.


## 5. Content Reporting

This section covers the content reporting functionality, a feature that allows users to report messages in violation of organizational guidelines to workspace administrators.

### Policies

#### GWS.CHAT.5.1v1
Chat content reporting SHALL be enabled for all conversation types.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)
[![Log-Based Check](https://img.shields.io/badge/Log--Based_Check-F6E8E5)](../../docs/usage/Limitations.md#log-based-policy-checks)

- _Rationale:_ Chat messages could be used as an avenue for phishing, malware distribution, or other security risks. Enabling this feature allows users to report any suspicious messages to Google Workspace (GWS) admins, increasing threat awareness and facilitating threat mitigation. By selecting all conversation types, agencies help enable their users to report risky messages regardless of the conversation type.
- _Last modified:_ February 2024
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ IR-6
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.CHAT.5.2v1
All reporting message categories SHOULD be selected.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)
[![Log-Based Check](https://img.shields.io/badge/Log--Based_Check-F6E8E5)](../../docs/usage/Limitations.md#log-based-policy-checks)

- _Rationale:_ Users may be uncertain about what kind of messages should be reported. Enabling all message categories can help users determine which types of messages should be reported.
- _Last modified:_ February 2024
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ IR-6
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources
- [Set-up content moderation for Chat](https://support.google.com/a/answer/13471510?hl=en)

### Prerequisites
-   Chat history must be enabled for users to be able to report messages.

### Implementation

#### GWS.CHAT.5.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Chat**.
3.  Click **Content reporting**.
4.  Ensure **Allow users to report content in Chat** is enabled.
5.  Ensure all conversation type checkboxes are selected.
6.  Click **Save**.

#### GWS.CHAT.5.2v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Chat**.
3.  Click **Content reporting**.
4.  Ensure all checkboxes under **Reporting categories** are selected.
5.  Click **Save**.
