# CISA Google Workspace Secure Configuration Baseline for Google Chat

Google Chat is a communication and collaboration tool in Google Workspace that supports direct messaging, group conversations, content creation, and sharing. Chat allows administrators to control and manage their messages and files. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Chat security.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-Federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Google Chat settings](https://support.google.com/a/answer/9540647?hl=en) and addresses the following:

-   [Chat History](#1-chat-history)
-   [External File Sharing](#2-external-file-sharing)
-   [History for Spaces](#3-history-for-spaces)
-   [External Chat Messaging](#4-external-chat-messaging)
-   [Content Reporting](#5-content-reporting)

Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Chat History

This section covers chat history retention for users within the organization and prevents users from changing their history setting. This control applies to both direct messages and group messages.

### Policies

#### GWS.CHAT.1.1v0.5
Chat history SHALL be enabled for information traceability.

- _Rationale:_ Users engaged in Google Chat may inadvertently share sensitive or private information during conversations and details discussed in chats may be crucial for future reference or dispute resolution. Enabling chat history for Google Chat may mitigate these risks by providing a traceable record of all conversations, enhancing information accountability and security.
- _Last modified:_ July 2023

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

#### GWS.CHAT.1.2v0.5
Users SHALL NOT be allowed to change their history setting.

- _Rationale:_ Altering the history settings in Google Chat can potentially allow users to obfuscate the sharing of sensitive information via Chat. This policy ensures that all chat histories are preserved, enhancing data security and promoting accountability among users.
- _Last modified:_ July 2023

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

### Resources

-   [Google Workspace Admin Help: Turn chat history on or off for users](https://support.google.com/a/answer/7664184)

### Prerequisites

-   None

### Implementation

To configure the settings for History for chats:

#### GWS.CHAT.1.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **History for chats**.
4.  Select **History is ON**.
5.  Select **Save**

#### GWS.CHAT.1.2v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **History for chats**.
4.  Uncheck the **Allow users to change their history setting** checkbox.
5.  Select **Save**.

## 2. External File Sharing

This section covers what types of files users are allowed to share external to their organization.

### Policies

#### GWS.CHAT.2.1v0.5
External file sharing SHALL be disabled to protect sensitive information from unauthorized or accidental sharing.

- _Rationale:_ Enabling external file sharing in Google Chat opens an additional avenue for data loss, one that may not be as rigorously monitored or protected as traditional collaboration channels, such as email. This policy limits the potential for unauthorized or accidental sharing.
- _Last modified:_ July 2023

- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources

-   [Google Workspace Admin Help: Control file sharing in Chat](https://support.google.com/a/answer/10277783?hl=en)

### Prerequisites

-   None

### Implementation

To configure the settings for External filesharing:

#### GWS.CHAT.2.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **Chat File Sharing**.
4.  In the **External filesharing** dropdown menu, select **No files.**
5.  Select **Save**.

## 3. History for Spaces

This section covers whether chat history is retained by default for users within the organization. This control does not apply for threaded chat spaces because those require that history be on, which cannot be changed. Chat spaces allow for multiple users to share files, assign tasks, and stay connected.

### Policies

#### GWS.CHAT.3.1v0.5
Space history SHOULD be enabled for traceability of information.

- _Rationale:_ Users engaged in Google Chat may inadvertently share sensitive or private information during conversations. Details discussed in chats may be crucial for future reference or dispute resolution. Enabling chat history for Google Chat may mitigate these risks by providing a traceable record of all conversations, enhancing information accountability and security.
- _Last modified:_ July 2023

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

### Resources

-   [Google Workspace Admin Help: Set a space history option for users](https://support.google.com/a/answer/9948515?hl=en)

### Prerequisites

-   None

### Implementation

To configure the settings for History for spaces:

#### GWS.CHAT.3.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3.  Select **History for spaces**.
4.  Select **History is ON by default** or **History is ALWAYS ON**.
5.  Select **Save**.

## 4. External Chat Messaging

This section permits users to send Chat messages outside of their organization, but such Chat messages must be restricted to allowlisted domains only.

### Policies

#### GWS.CHAT.4.1v0.5
External Chat messaging SHALL be restricted to allowlisted domains only.

- _Rationale:_ Allowing external chat messaging in Google Chat to unrestricted domains opens additional avenues for data exfiltration, increasing the risk of data leakage. By restricting external chat messaging to allowlisted domains only, the risk of sensitive information being distributed outside the organization without explicit consent and approval is minimized.
- _Last modified:_ November 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Set external chat options](https://support.google.com/a/answer/9269229?product_name=UnuFlow&visit_id=637841711304802210-4105703050&rd=1&src=supportwidget0)
-   [Google Workspace Admin Help: Allow external sharing with only trusted domains](https://support.google.com/a/answer/6160020)
-   [CIS Google Workspace Benchmark v1.1.0 - 3.1.4.2.2 Ensure Google Chat Externally is Restricted to Allowlisted Domains](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for External Chat:

#### GWS.CHAT.4.1v0.5 Instructions
To enable external chat for allowlisted domains only:
1. Sign in to the [Google Admin Console](https://admin.google.com).
2. Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3. Select **External Chat Settings** -\> **Chat externally**.
4. Select **ON**
5. Select **Only allow this for allowlisted domains**.
6. To add allowlisted domains select **Manage allowlisted domains**.
7. Select **Save**.

Alternatively, to disable external chat entirely:
1. Sign in to the [Google Admin Console](https://admin.google.com).
2. Select **Apps** -\> **Google Workspace** -\> **Google Chat**.
3. Select **External Chat Settings** -\> **Chat externally**.
4. Select **OFF**
5. Select **Save**.


## 5. Content Reporting

This section covers the content reporting functionality, a feature that allows users to report messages that violate organizational guidelines to workspace admins.

### Policies

#### GWS.CHAT.5.1v0.5
Chat content reporting SHALL be enabled for all conversation types.

- _Rationale:_ Chat messages could potentially be used as an avenue for phishing, malware distribution, or other security risks. Enabling this feature allows users to report any suspicious messages to workspace admins, increasing threat awareness and facilitating threat mitigation. By selecting all conversation types, agencies help ensure that their users are able to report risky messages regardless of the conversation type.
- _Last modified:_ February 2024

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.CHAT.5.2v0.5
All reporting message categories SHOULD be selected.

- _Rationale:_ Users may be uncertain what kind of messages should be reported. Enabling all message categories can help users infer which types of messages should be reported.
- _Last modified:_ February 2024

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources
- [Set-up content moderation for Chat](https://support.google.com/a/answer/13471510?hl=en)

### Prerequisites
-   Chat history must be enabled for users to be able to report messages.

### Implementation

#### GWS.CHAT.5.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Chat**.
3.  Click **Content Reporting**.
4.  Ensure **Allow users to report content in Chat** is enabled.
5.  Ensure all conversation type checkboxes are selected.
6.  Click **Save**.

#### GWS.CHAT.5.2v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Chat**.
3.  Click **Content Reporting**.
4.  Ensure all checkboxes under **Reporting Categories** are selected.
5.  Click **Save**.
