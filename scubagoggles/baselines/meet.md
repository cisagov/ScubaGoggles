# CISA Google Workspace Secure Configuration Baseline for Google Meet

Google Meet is a video conferencing service in Google Workspace that supports real-time video, desktop, and presentation sharing. Meet allows administrators to control and manage their video meetings. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Meet security.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-Federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Meet settings reference for admins](https://support.google.com/a/answer/7304109?product_name=UnuFlow&hl=en&visit_id=637812507975083818-2789839413&rd=1&src=supportwidget0&hl=en#:~:text=From%20the%20Admin%20console%20Home%20page%2C%20go%20to,to%20everyone%2C%20leave%20the%20top%20organizational%20unit%20selected) and addresses the following:

-   [Meeting Access](#1-meeting-access)
-   [Internal Access to External Meetings](#2-internal-access-to-external-meetings)
-   [Host Management Meeting Features](#3-host-management-meeting-features)
-   [External Participants](#4-external-participants)
-   [Incoming Calls](#5-incoming-calls)
-   [Video Meeting Settings](#6-video-meeting-settings)


Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Automated Check**: This indicator means that the policy can be automatically checked via ScubaGoggles. See the [Quick Start Guide](../../README.md) for help getting started.

**Manual**: This indicator means that the policy requires manual verification of configuration settings.

# Baseline Policies

## 1. Meeting Access

This control limits external users not explicitly invited to the meeting from joining without permission.

### Policies

#### GWS.MEET.1.1v0.6
External users who were not explicitly invited SHALL be required to ask to join.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Allowing users not within the organization or those not on the invite list to join meetings without asking diminishes host control of meeting participation, reduces user accountability, and invites potential data breach. This policy reduces that risk by requiring users outside the organization or without an invitation to require organizer permission to join.
- _Last modified:_ November 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ IA-2, IA-8
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1123: Audio Capture](https://attack.mitre.org/techniques/T1123/)
  - [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/)
  - [T1125: Video Capture](https://attack.mitre.org/techniques/T1125/)

### Resources

-   [Google Meet security & privacy for admins](https://support.google.com/a/answer/7582940?hl=en&ref_topic=7302923#zippy=%2Cprivacy-compliance%2Cincident-response%2Csecure-deployment-access-controls%2Canti-abuse-measures%2Cencryption%2Csafety-best-practices)
-   [Google Meet settings reference for admins](https://support.google.com/a/answer/7304109?product_name=UnuFlow&hl=en&visit_id=637812507975083818-2789839413&rd=1&src=supportwidget0&hl=en#:~:text=From%20the%20Admin%20console%20Home%20page%2C%20go%20to,to%20everyone%2C%20leave%20the%20top%20organizational%20unit%20selected)

### Prerequisites

-   None

### Implementation

To configure the settings for Access type Meet safety settings:

#### GWS.MEET.1.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Access Type**.
4.  In **Meeting access type (subject to restrictions set in Domain)**, select **Trusted** or **Restricted**.
5.  Select **Save**.


## 2. Internal Access to External Meetings

This control determines which meetings users within the agency's organization can join.

### Policies

#### GWS.MEET.2.1v0.6
Meeting access SHALL be disabled for meetings created by users who are not members of any Google Workspace tenant or organization.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Contact with unmanaged users can pose the risk of data leakage and other security threats. This policy reduces such contact by not allowing agency users to join meetings created by users' personal accounts.
- _Last modified:_ September 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ IA-8, SC-7(10)
- MITRE ATT&CK TTP Mapping
  - [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
  - [T1123: Audio Capture](https://attack.mitre.org/techniques/T1123/)
  - [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/)
  - [T1125: Video Capture](https://attack.mitre.org/techniques/T1125/)

### Resources

-   [Google Meet security & privacy for admins](https://support.google.com/a/answer/7582940?hl=en&ref_topic=7302923#zippy=%2Cprivacy-compliance%2Cincident-response%2Csecure-deployment-access-controls%2Canti-abuse-measures%2Cencryption%2Csafety-best-practices)
-   [Google Meet settings reference for admins](https://support.google.com/a/answer/7304109?product_name=UnuFlow&hl=en&visit_id=637812507975083818-2789839413&rd=1&src=supportwidget0&hl=en#:~:text=From%20the%20Admin%20console%20Home%20page%2C%20go%20to,to%20everyone%2C%20leave%20the%20top%20organizational%20unit%20selected)

### Prerequisites

-   None

### Implementation

To configure the settings for Access within Meet safety settings:

#### GWS.MEET.2.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Access**.
4.  Select **Meetings created in your organization only** or **Meetings created in any Workspace organization**.
5.  Select **Save**.

## 3. Host Management Meeting Features

This control enables the following features for a host to implement during their meeting: prevent participants from sharing their screen, turn chat messages on or off, end the meeting for all, and mute all. By default, this control is disabled.

Note: When this feature is not enabled, any attendee that is a member of the host's organization can record the meeting.

### Policies

#### GWS.MEET.3.1v0.6
Host Management meeting features SHALL be enabled.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ With host management disabled, any internal participant is able to take control of meetings, performing actions such as recording the meeting, disabling or enabling the chat, and ending the meeting. When enabled, these options are only available to meeting hosts.
- _Last modified:_ January 2024
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ CM-7
- MITRE ATT&CK TTP Mapping
  - [T1562:001: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
  - [T1123: Audio Capture](https://attack.mitre.org/techniques/T1123/)
  - [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/)
  - [T1125: Video Capture](https://attack.mitre.org/techniques/T1125/)

### Resources

-   [Google Meet security & privacy for admins](https://support.google.com/a/answer/7582940?hl=en&ref_topic=7302923#zippy=%2Cprivacy-compliance%2Cincident-response%2Csecure-deployment-access-controls%2Canti-abuse-measures%2Cencryption%2Csafety-best-practices)
-   [Google Meet settings reference for admins](https://support.google.com/a/answer/7304109?product_name=UnuFlow&hl=en&visit_id=637812507975083818-2789839413&rd=1&src=supportwidget0&hl=en#:~:text=From%20the%20Admin%20console%20Home%20page%2C%20go%20to,to%20everyone%2C%20leave%20the%20top%20organizational%20unit%20selected)
-   [Record a Video Meeting](https://support.google.com/meet/answer/9308681?hl=en)

### Prerequisites

-   None

### Implementation

To enable Host Management meeting features:

#### GWS.MEET.3.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Host management**.
4.  Check the **Start video calls with host management turned on** checkbox.
5.  Select **Save**.

## 4. External Participants

This control provides a warning label for any participating a meeting who is not a member of the organization or whose identity is unconfirmed.

### Policies

#### GWS.MEET.4.1v0.6
Warn for external participants SHALL be enabled.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Users may inadvertently include external users or not be aware that external users are present. When enabled, external or unidentified participants in a meeting are given a label. This increases situational awareness amongst meeting participants and can help prevent inadvertent data leakage.
- _Last modified:_ September 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-15
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:004: Phishing: Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)
  - [T1598: Phishing for Information](https://attack.mitre.org/techniques/T1598/)
    - [T1598:004: Phishing for Information: Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004/)
  - [T1123: Audio Capture](https://attack.mitre.org/techniques/T1123/)
  - [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/)
  - [T1125: Video Capture](https://attack.mitre.org/techniques/T1125/)

### Resources

-   [Manage Meet settings (for admins)](https://support.google.com/a/answer/7304109?fl=1&sjid=1761497708922707326-NA)

### Prerequisites

-   None

### Implementation

To enable Host Management meeting features:

#### GWS.MEET.4.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Warn for external participants**.
4.  Check the **External or unidentified participants in a meeting are given a label** checkbox.
5.  Select **Save**.

## 5. Incoming Calls

This section covers who domain users are allowed to receive a 1:1 call from.

### Policies

#### GWS.MEET.5.1v0.6
Incoming calls SHALL be restricted to contacts and other users in the organization.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Calls could potentially be used to pass sensitive information. By selecting this setting, it potentially mitigates unauthorized data leakage.
- _Last modified:_ March 2024
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SI-8, SC-15a
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:004: Phishing: Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)
  - [T1598: Phishing for Information](https://attack.mitre.org/techniques/T1598/)
    - [T1598:004: Phishing for Information: Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004/)
  - [T1123: Audio Capture](https://attack.mitre.org/techniques/T1123/)
  - [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/)
  - [T1125: Video Capture](https://attack.mitre.org/techniques/T1125/)

### Resources
- [Restrict who can call my organization's users with Google Meet](https://support.google.com/a/answer/14277985)

### Prerequisites
-   None

### Implementation

#### GWS.MEET.5.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Meet**.
3.  Click **Meet safety settings**.
4.  Click **Incoming call restrictions**.
5.  Ensure **Users receive calls only from contacts and other users in the organization** or **Users can't receive calls** is selected.
6.  Click **Save**.

## 6. Video Meeting Settings

This section covers Google Meet video settings such as automatic video recording and automatic transcription.

### Policies

#### GWS.MEET.6.1v0.6
Automatic recordings for Google Meet SHALL be disabled.

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwsmeet61v06-instructions)

- _Rationale:_ Automatic recordings could record sensitive information. By selecting this setting, it potentially mitigates unauthorized data leakage.
- _Last modified:_ January 2024
- _Note:_ The meeting owner retains the ability to modify this setting for their own meetings.
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ CM-7
- MITRE ATT&CK TTP Mapping
  - [T1123: Audio Capture](https://attack.mitre.org/techniques/T1123/)
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
  - [T1565: Data Manipulation](https://attack.mitre.org/techniques/T1565/)

#### GWS.MEET.6.2v0.6
Automatic transcripts for Google Meet SHALL be disabled.

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwsmeet62v06-instructions)

- _Rationale:_ Automatic transcripts could record sensitive information. By selecting this setting, it potentially mitigates unauthorized data leakage.
- _Last modified:_ January 2024
- _Note:_ The meeting owner retains the ability to modify this setting for their own meetings.
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ CM-7
- MITRE ATT&CK TTP Mapping
  - [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/)
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
  - [T1565: Data Manipulation](https://attack.mitre.org/techniques/T1565/)


### Resources
- [Choose automatic meeting artifact settings for your organization](https://support.google.com/a/answer/15496523?p=automaticmeetingrecords)

### Prerequisites
-   None

### Implementation

#### GWS.MEET.6.1v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Meet**.
3.  Click **Meet video settings**.
4.  Click **Automatic recording**.
5.  Ensure **Meetings are recorded by default** is unselected.
6.  Click **Save**.

#### GWS.MEET.6.2v0.6 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu** -> **Apps** -> **Google Workspace** -> **Google Meet**.
3.  Click **Meet video settings**.
4.  Click **Automatic transcription**.
5.  Ensure **Meetings are transcribed by default** is unselected.
6.  Click **Save**.
