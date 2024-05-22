# CISA Google Workspace Security Configuration Baseline for Google Meet

Google Meet is a video conferencing service in Google Workspace that supports real-time video, desktop, and presentation sharing. Meet allows administrators to control and manage their video meetings. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Meet security.

The Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments. The SCuBA Secure Configuration Baselines (SCB) for Google Workspace (GWS) will help secure federal civilian executive branch (FCEB) information assets stored within GWS cloud environments through consistent, effective, modern, and manageable security configurations.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA.

This baseline is based on Google documentation available at [Google Meet settings reference for admins](https://support.google.com/a/answer/7304109?product_name=UnuFlow&hl=en&visit_id=637812507975083818-2789839413&rd=1&src=supportwidget0&hl=en#:~:text=From%20the%20Admin%20console%20Home%20page%2C%20go%20to,to%20everyone%2C%20leave%20the%20top%20organizational%20unit%20selected) and addresses the following:

-   [Meeting Access](#1-meeting-access)
-   [Internal Access to External Meetings](#2-internal-access-to-external-meetings)
-   [Host Management Meeting Features](#3-host-management-meeting-features)
-   [External Participants](#4-external-participants)


Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Meeting Access

This control limits safe meeting access to users with a Google Account or Dialing in using a phone.

### Policies

#### GWS.MEET.1.1v0.1
Meeting access SHOULD be restricted to users signed in with a Google Account or Dialing in using a phone.

- _Rationale:_ Allowing users not signed-in to join meetings diminishes host control of meeting participation, reduces user accountability, and invites potential data breach. This policy reduces that risk by requiring all users to sign-in.
- _Last modified:_ June 29, 2023
- _Note:_ There is a related configuration option shown to the meeting organizer within Google Meet itself, called "Meeting access type." The setting in the admin center restricts at the org-level the types of users able to join meetings. The setting shown to the meeting organizer allows the organizer to specify who, of those permitted to join meetings by the org-wide setting, must ask to join their meeting. This baseline only provides guidance on the org-wide setting; the per-meeting setting MAY be set as each agency sees fit.

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

To configure the settings for Domain Meet safety settings:

#### GWS.MEET.1.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Domain**.
4.  Select **Only users from your organization or users dialing in using a phone** or **Users signed in with a Google account or dialing in using a phone**.
5.  Select **Save**.


## 2. Internal Access to External Meetings

This control determines which meetings users within the agency's organization can join.

### Policies

#### GWS.MEET.2.1v0.1
Meeting access SHALL be disabled for meetings created by users who are not members of any Google Workspace tenant or organization.

- _Rationale:_ Contact with unmanaged users can pose the risk of data leakage and other security threats. This policy reduces such contact by not allowing agency users to join meetings created by users' personal accounts.
- _Last modified:_ September 26, 2023

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

#### GWS.MEET.2.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Access**.
4.  Select **Meetings created in your organization only** or **Meetings created in any Workspace organization**.
5.  Select **Save**.

## 3. Host Management Meeting Features

This control enables the following features for a host to implement during their meeting: prevent participants from sharing their screen, turn chat messages on or off, end the meeting for all, and mute all. By default, this control is disabled.

Note: When this feature is not enabled, any attendee that is a member of the host's organization can record the meeting.

### Policies

#### GWS.MEET.3.1v0.1
Host Management meeting features SHALL be enabled.

- _Rationale:_ With host management disabled, any internal participant is able to take control of meetings, performing actions such as recording the meeting, disabling or enabling the chat, and ending the meeting. When enabled, these options are only available to meeting hosts.
- _Last modified:_ January 10, 2024

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

#### GWS.MEET.3.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Host management**.
4.  Check the **Start video calls with host management turned on** checkbox.
5.  Select **Save**.

## 4. External Participants

This control provides a warning label for any participating a meeting who is not a member of the organization or whose identity is unconfirmed.

### Policies

#### GWS.MEET.4.1v0.1
Warn for external participants SHALL be enabled.

- _Rationale:_ Users may inadvertently include external users or not be aware that external users are present. When enabled, external or unidentified participants in a meeting are given a label. This increases situational awareness amongst meeting participants and can help prevent inadvertent data leakage.
- _Last modified:_ September 26, 2023

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

#### GWS.MEET.4.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Google Meet**.
3.  Select **Meet safety settings** -\> **Warn for external participants**.
4.  Check the **External or unidentified participants in a meeting are given a label** checkbox.
5.  Select **Save**.
