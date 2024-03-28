# CISA Google Workspace Security Configuration Baseline for Groups for Business

Groups for Business is a Google Workspace collaboration tool that supports storage, access, and sharing of files, document management, and email. Groups for Business allows administrators to control and manage collaboration efforts among groups within their organizations. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Groups security.

The Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments. The SCuBA Secure Configuration Baselines (SCB) for Google Workspace (GWS) will help secure federal civilian executive branch (FCEB) information assets stored within GWS cloud environments through consistent, effective, modern, and manageable security configurations.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Set up and manage Groups for Business](https://support.google.com/a/topic/9400092?hl=en&ref_topic=25838) and addresses the following:

-   [External Group Access](#1-external-group-access)
-   [Adding External Members](#2-adding-external-members)
-   [Allowing Posting by External Members](#3-allowing-posting-by-external-members)
-   [Group Creation](#4-group-creation)
-   [Default Permissions for Viewing Conversations](#5-default-permissions-for-viewing-conversations)
-   [Ability to Hide Groups from the Directory](#6-ability-to-hide-groups-from-the-directory)
-   [New Groups](#7-new-groups)

Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.


# Baseline Policies

## 1. External Group Access

This control determines whether users outside of an agency's organization can view, search for, or post to groups internal to an agency.

Note: Even with this setting configured, group owners can still explicitly add external POCs to a group ([Adding External Members](#2-adding-external-members)), or explicitly allow posting to a group by an external POC who has not been added to said group ([Allowing Posting by External Members](#3-allowing-posting-by-external-members)).

### Baseline Policies

#### GWS.GROUPS.1.1v0.1
Group access from outside the organization SHALL be disabled unless explicitly granted by the group owner.

- _Rationale:_ Groups may contain private or sensitive information. Restricting group access reduces the risk of data loss.
- _Last Modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Set organization-wide policies for using groups](https://support.google.com/a/answer/167097?hl=en&ref_topic=9400092)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.GROUPS.1.1v0.1 Instructions
To configure the settings for Sharing options:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Groups for Business**.
3.  Select **Sharing settings** -\> **Sharing options**.
4.  Select **Accessing groups from outside this organization** -\> **Private**.
5.  Select **Save**.

## 2. Adding External Members

This section covers whether or not the owner of the group has the ability to add external members to the group.

### Policies

#### GWS.GROUPS.2.1v0.1
Group owners' ability to add external members to groups SHOULD be disabled unless necessary for agency mission fulfillment.

- _Rationale:_ Groups may contain private or sensitive information. Restricting group access reduces the risk of data loss.
- _Last Modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1048: Exfilitration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfilitration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfilitration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources

-   [Google Workspace Admin Help: Set organization-wide policies for using groups](https://support.google.com/a/answer/167097?hl=en&ref_topic=9400092)

### Prerequisites

-   None

### Implementation

#### GWS.GROUPS.2.1v0.1 Instructions
To configure the settings for Sharing options:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Groups for Business**.
3.  Select **Sharing settings** -\> **Sharing options**.
4.  **Uncheck** the **Group owners can allow external members** checkbox.
5.  Select **Save**.

## 3. Allowing Posting by External Members

This section covers whether or not an owner of a group has the ability to allow an external non-member to post to the group.

### Policies

#### GWS.GROUPS.3.1v0.1
Group owners' ability to allow posting to a group by an external, non-group member SHOULD be disabled unless necessary for agency mission fulfillment.

- _Rationale:_ Allowing external users to post opens the door for phishing or other malicious activity to be shared via Groups. Restricting posting by non-group members reduces this risk.
- _Last Modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1048: Exfilitration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfilitration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfilitration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Resources

-   [Google Workspace Admin Help: Set organization-wide policies for using groups](https://support.google.com/a/answer/167097?hl=en&ref_topic=9400092)

### Prerequisites

-   None

### Implementation

#### GWS.GROUPS.3.1v0.1 Instructions
To configure the settings for Sharing options:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Groups for Business**.
3.  Select **Sharing settings** -\> **Sharing options**.
4.  **Uncheck** the **Group owners can allow incoming mail from outside the organization** checkbox.
5.  Select **Save**.

## 4. Group Creation

This section covers who has the ability to create a new group within the organization.

### Policies

#### GWS.GROUPS.4.1v0.1
Group creation SHOULD be restricted to admins within the organization unless necessary for agency mission fulfillment.

- _Rationale:_ Many settings for Google Workspace products can be set at the Group level. Allowing unrestricted group creation complicates setting management and opens channels of unmanaged communication.
- _Last Modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1069: Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
    - [T1069:003: Permission Groups Discovery: Cloud Groups](https://attack.mitre.org/techniques/T1069/003/)

### Resources

-   [Google Workspace Admin Help: Set organization-wide policies for using groups](https://support.google.com/a/answer/167097?hl=en&ref_topic=9400092)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.GROUPS.4.1v0.1 Instructions
To configure the settings for Sharing options:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Groups for Business**.
3.  Select **Sharing settings** -\> **Sharing options**.
4.  Select **Creating groups** -\> **Only organization admins can create groups**.
5.  Select **Save**.

## 5. Default Permissions for Viewing Conversations

This section covers the default permissions assigned to the viewing of conversations within a group.

### Policies

#### GWS.GROUPS.5.1v0.1
The default permission to view conversations SHOULD be set to All Group Members.

- _Rationale:_ Groups may contain private or sensitive information. Restricting group access reduces the risk of data loss.
- _Last Modified:_ July 10, 2023
- _Note:_ This setting can be changed by group owners and group managers.

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1048: Exfilitration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfilitration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfilitration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources

-   [Google Workspace Admin Help: Set organization-wide policies for using groups](https://support.google.com/a/answer/167097?hl=en&ref_topic=9400092)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.GROUPS.5.1v0.1 Instructions
To configure the settings for Sharing options:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Groups for Business**.
3.  Select **Sharing settings** -\> **Sharing options**.
4.  Select **Default for permission to view conversations** -\> **All group members**.
5.  Select **Save**.

## 6. Ability to Hide Groups from the Directory

This section covers whether or not the owner of a group can hide the group from the directory.

### Policies

#### GWS.GROUPS.6.1v0.1
The Ability for Groups to be Hidden from the Directory SHALL be disabled.

- _Rationale:_ Hidden groups are not visible, even to admins, in the list of groups found at groups.google.com, though they are still visible on the directory page on admin.google.com. As such, allowing for hidden groups increases the risk of groups being created without admin oversight.
- _Last Modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1048: Exfilitration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfilitration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfilitration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources

-   [Google Workspace Admin Help: Set organization-wide policies for using groups](https://support.google.com/a/answer/167097?hl=en&ref_topic=9400092)

### Prerequisites

-   None

### Implementation

#### GWS.GROUPS.6.1v0.1 Instructions
To configure the settings for Sharing options:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Groups for Business**.
3.  Select **Sharing settings** -\> **Sharing options**.
4.  **Uncheck** the **Group owners can hide groups from the directory** checkbox.
5.  **Ensure** that the **hide newly created groups from the directory** checkbox is not selected.
6.  Select **Save**.

## 7. New Groups

This section covers the access type setting for new groups that are created.

### Policies

#### GWS.GROUPS.7.1v0.1
New Groups SHOULD be created with an Access type of Restricted unless necessary for agency mission fulfillment.

- _Rationale:_ Allowing external users to post opens the door for phishing or other malicious activity to be shared via Groups.
- _Last Modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1069: Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
    - [T1069:003: Permission Groups Discovery: Cloud Groups](https://attack.mitre.org/techniques/T1069/003/)

### Resources

- [Google Workspace Admin Help: Create a group in your organization](https://github.com/mitre/CISA-SCuBA-GWS-SCB)

### Prerequisites

- This control only applies to agencies with Google Groups for Business enabled.

### Implementation

#### GWS.GROUPS.7.1v0.1 Instructions
To configure Access type for a Google Group:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Directory** -\> **Groups.**
3.  Select **Create group.**
4.  Fill in the details for the new group and click **Next.**
5.  In the **Access type** section, select the **Restricted** radio button.
6.  If the group needs to receive messages from non-members, select the appropriate checkboxes in the **Who can post** row.
7.  Select **Next.**
8.  Select **Create Group.**
