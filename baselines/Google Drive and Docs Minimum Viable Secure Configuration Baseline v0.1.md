# CISA Google Workspace Secure Configuration Baseline for Google Drive and Docs

Google Drive and Docs are collaboration tools in Google Workspace that support document management and storage, access, and sharing of files. Drive and Docs allow administrators to control and manage their files and documents. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Drive and Docs security.

The Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments. The SCuBA Secure Configuration Baselines (SCB) for Google Workspace (GWS) will help secure federal civilian executive branch (FCEB) information assets stored within GWS cloud environments through consistent, effective, modern, and manageable security configurations.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Overview: Manage Drive for an organization](https://support.google.com/a/answer/2490026?hl=en) and addresses the following:

-   [Sharing Outside the Organization](#1-sharing-outside-the-organization)
-   [Shared Drive Creation](#2-shared-drive-creation)
-   [Security Updates for Files](#3-security-updates-for-files)
-   [Drive SDK](#4-drive-sdk)
-   [User Installation of Drive and Docs Add-Ons](#5-user-installation-of-drive-and-docs-add-ons)
-   [Drive for Desktop](#6-drive-for-desktop)
-   [DLP Rules](#7-dlp-rules)

Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Sharing Outside the Organization

This section covers whether users can share files outside of the organization, whether Google checks a shared file to ensure that recipients have access, and which users have permission to distribute content outside of the organization to include uploading or moving content to shared drives owned by another organization. These files include Google Docs, Sheets, Slides, My Maps, folders, and anything else stored in Drive.

### Policies

#### GWS.DRIVEDOCS.1.1v0.1
Agencies SHOULD disable sharing outside of the organization's domain.

- _Rationale:_ Documents may contain sensitive or private information. Disabling external sharing reduces the risk of inadvertent of data leakage.
- _Last modified:_ July 10, 2023
- _Note:_
  - This policy restricts information sharing
  - This policy prevents data leakage outside of the organization
  - If this policy is enforced, then follow Policy 1.2
  - If this policy is not enforced, then follow Policies 1.3 and 1.4
  - Regardless, policies 1.5 through 1.8 must be followed

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.2v0.1
Agencies SHOULD disable users' receiving files from outside of the organization's domain.

- _Rationale:_ Users given access to external files may inadvertently input sensitive or private content. Additionally, files created externally may contain malicious content. Disallowing external files from being shared to your users may reduce the risk of data loss or falling victim to external threats.
- _Last modified:_ January 3, 2024
- _Note:_ This policy only applies if sharing outside was disabled in Policy 1.1

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.3v0.1
Warnings SHALL be enabled when a user is attempting to share something outside the domain.

- _Rationale:_ Users may not always be aware a given user is external to their organization. Warning them before sharing increases user awareness and accountability.
- _Last modified:_ February 8, 2024
- _Note:_ This policy only applies if external sharing was allowed in Policy 1.1

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.4v0.1
If sharing outside of the organization, then agencies SHALL disable sharing of files with individuals who are not using a Google account.

- _Rationale:_ Allowing users not signed-in to a Google account to view shared files diminishes oversight and accountability and invites potential data breach. This policy reduces that risk by requiring all people to be signed in when viewing shared Doc/Drive materials.
- _Last modified:_ July 10, 2023
- _Note:_ This policy only applies if external sharing is allowed in Policy 1.1

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.5v0.1
Agencies SHALL disable making files and published web content visible to anyone with the link.

- _Rationale:_ Allowing users not signed-in to a Google account to view shared files diminishes oversight and accountability and invites potential data breach. This policy reduces that risk by requiring all people to be signed in when viewing shared Doc/Drive materials.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.6v0.1
Agencies SHALL enable access checking for file sharing outside of Docs or Drive.

- _Rationale:_ The Access Checker feature can be configured to allows users to grant access to the public if a recipient is missing access, creating the potential for data leakage. This control mitigates this by only allowing access to be granted to recipients or the suggested target audience.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.7v0.1
Agencies SHALL NOT allow any users to distribute content from an organization-owned shared drive to shared drives owned by another organization.

- _Rationale:_ Once a document is moved outside the organization's drives, the organization no longer has control over the dissemination of the document. By not allowing users to distribute content to external shared drives, the organization maintains more control over the document.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.DRIVEDOCS.1.8v0.1
Agencies SHALL set newly created items to have Private to the Owner as the default level of access.

- _Rationale:_ By implementing least privilege and setting the default to be private, the organization is able to prevent accidental sharing of information too broadly.
- _Last modified:_ November 14, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
  - [T1538: Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)

### Resources

-   [Google Workspace Admin Help: Set Drive users' sharing permissions](https://support.google.com/a/answer/60781?hl=en)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for Sharing options:

#### Policy Group 1 Common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Drive and Docs**.
4.  Follow implementation for each individual policy
5.  Select **Save**

#### GWS.DRIVEDOCS.1.1v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Select **Sharing outside of your domain** -\> **OFF – Files owned by users in your domain cannot be shared outside of your domain**

#### GWS.DRIVEDOCS.1.2v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Deselect **Allow users to receive files from users or shared drives outside of the organization**

#### GWS.DRIVEDOCS.1.3v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Select **Warn when files owned by users or shared drives in your organization are shared outside of your organization.**

#### GWS.DRIVEDOCS.1.4v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Deselect **Allow users or shared drives in your organization to share items with people outside of your organization who aren't using a Google account.**

#### GWS.DRIVEDOCS.1.5v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Deselect **When sharing outside of your organization is allowed, users in your organization can make files and published web content visible to anyone with the link.**

#### GWS.DRIVEDOCS.1.6v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Select **Access Checker** -\> **Recipients only, or suggested target audience.**

#### GWS.DRIVEDOCS.1.7v0.1 Instructions
1.  Select **Sharing settings** -\> **Sharing options**.
2.  Select **Distributing content outside of your domain** -\> **No one**

#### GWS.DRIVEDOCS.1.8v0.1 Instructions
1.  Select **Sharing settings -\> General access default.**
2.  Select **When users in your organization create items, the default access will be -\> Private to the owner.**

## 2. Shared Drive Creation

This section covers whether users can create new shared drives to share with other users, including those external to their organization. Even if users cannot create new shared drives, they can still be added to shared drives owned by other users. This control also determines which users, both internal and external to the organization, can access files in shared drives.

### Policies

#### GWS.DRIVEDOCS.2.1v0.1
Agencies SHOULD NOT allow members with manager access to override shared drive creation settings.

- _Rationale:_ Allowing users who are not the drive owner to override settings violates the principle of least privilege. This policy reduces the risk of drive settings being modified by unauthorized individuals.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.DRIVEDOCS.2.2v0.1
Agencies SHOULD NOT allow users outside of their organization to access files in shared drives.

- _Rationale:_ To regulate document access within the organization, it is recommended that agencies restrict external users from accessing files on shared drives. This policy is aimed at safeguarding internal documents from being distributed outside the organization without explicit consent and approval.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.DRIVEDOCS.2.3v0.1
Agencies SHALL allow users who are not shared drive members to be added to files.

- _Rationale:_ Prohibiting non-members from being added to a file necessitates their addition as drive members, potentially exposing all drive files and increasing the risk of sensitive content exposure. By disallowing the sharing of these individual files, the risk of internal documents from being distributed outside the organization without explicit consent and approval is decreased.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

#### GWS.DRIVEDOCS.2.4v0.1
Agencies SHALL NOT allow viewers and commenters to download, print, and copy files.

- _Rationale:_ Downloading and removing a file from the GWS tenant bypasses all access control settings, increasing the risk of data leakage. By preventing the sharing of these externally downloaded files, the risk of internal documents from being distributed outside the organization without explicit consent and approval is decreased.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources
-   [Google Workspace Admin Help: Set Drive users' sharing permissions](https://support.google.com/a/answer/60781?hl=en)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for Shared drive creation:

##### Policy Group 2 common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Google Workspace** -\> **Drive and Docs**.
3.  Select **Sharing settings -\> Shared drive creation**.
4.  Follow the implementation for each individual policy.
5.  Select **Save**

#### GWS.DRIVEDOCS.2.1v0.1 Instructions
1.  Uncheck the **Allow members with manager access to override the settings below** checkbox.

#### GWS.DRIVEDOCS.2.2v0.1 Instructions
1.  Uncheck the **Allow users outside organization to access files in shared drives** checkbox.

#### GWS.DRIVEDOCS.2.3v0.1 Instructions
1.  Check the **Allow people who aren't shared drive members to be added to files** checkbox.

#### GWS.DRIVEDOCS.2.4v0.1 Instructions
1.  Check the **Allow viewers and commenters to download, print, and copy files** checkbox.

## 3. Security Updates for Files

This section covers whether a security update issued by Google will be applied to make file links more secure. When sharing files using a link, users must not remove the resource key parameter, as doing so may result in unexpected file access requests.

### Policies

#### GWS.DRIVEDOCS.3.1v0.1
Agencies SHALL enable security updates for Drive files.

- _Rationale:_ Google may add new security features over time. Allowing security updates ensures that your files are protected with the latest features Google makes available.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Security update for Google Drive](https://support.google.com/drive/answer/10729743?hl=en#zippy=%2Care-any-file-types-not-impacted%2Cwhat-happens-if-i-dont-apply-the-security-update-to-my-files%2Chow-will-this-security-update-change-access-to-my-impacted-files)

### Prerequisites

-   None

### Implementation

To configure the settings for Security update for files:

##### GWS.DRIVEDOCS.3.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Drive and Docs.**
3.  Select **Sharing settings -\> Security update for files.**
4.  Select **Apply security update to all impacted files.**
5.  Uncheck the **Allow users to remove/apply the security update for files they own or manage** checkbox.
6.  Select **Save**.

## 4. Drive SDK

This section covers whether users have access to Google Drive with the Drive SDK API, which allows third party applications to work on the files that are stored in Google Drive. The Drive SDK API is used by developers to access Google Drive through third party applications that they have created.

### Policies

#### GWS.DRIVEDOCS.4.1v0.1
Agencies SHOULD disable Drive SDK access.

- _Rationale:_ The Drive SDK allows third-party applications to access Drive data, potentially leading to unintentional information sharing and data leakage. By disabling the Drive SDK you can decrease the risk of internal documents from being distributed outside the organization without explicit consent and approval.
- _Last modified:_ January 3, 2024

- MITRE ATT&CK TTP Mapping
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

### Resources

-   [Google Drive for Developers](https://developers.google.com/drive/)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for Drive SDK:

#### GWS.DRIVEDOCS.4.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Drive and Docs.**
3.  Select **Features and Applications -\> Drive SDK.**
4.  Uncheck the **Allow users to access Google Drive with the Drive SDK API** checkbox.
5.  Select **Save**.

## 5. User Installation of Drive and Docs Add-Ons

This section covers whether users can use add-ons in file editors within Google Drive, such as Docs, Sheets, Slides, and Forms. These add-ons include those available through Google Workspace Marketplace that have been built by other developers.

### Policies

#### GWS.DRIVEDOCS.5.1v0.1
Agencies SHALL disable Add-Ons.

- _Rationale:_ Google Docs Add-Ons, depending on their permissions, can present a security risk, including potential exposure of sensitive content. By disabling unapproved add-ons and preventing their sharing, the risk of data leakage can be significantly reduced.
- _Last modified:_ January 3, 2024

- MITRE ATT&CK TTP Mapping
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:001: Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)

### Resources

-   [Google Workspace Admin Help: Allow or restrict add-ons in Docs editors](https://support.google.com/a/answer/4530135?product_name=UnuFlow&visit_id=637843582622955886-2417503403&rd=1&src=supportwidget0)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure the settings for add-ons:

#### GWS.DRIVEDOCS.5.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Drive and Docs.**
3.  Select **Features and Applications -\> Add-Ons.**
4.  Uncheck the **Allow users to install Google Docs add-ons from add-ons stor**e checkbox.
5.  Select **Save**.

## 6. Drive for Desktop

This section addresses Drive for Desktop, a feature that enables users to interact with their Drive files directly through their desktop's file explorer or finder, rather than through the browser.

### Policies

#### GWS.DRIVEDOCS.6.1v0.1
Agencies SHOULD either disable Google Drive for Desktop or only allow Google Drive for Desktop on authorized devices.

- _Rationale:_ Some users may attempt to use Drive for Desktop to connect unapproved devices (e.g., a personal computer), to the agency's Google Drive. Even if done without malicious intent, this represents a security risk as the agency has no ability audit or protect such computers.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Use Google Drive for desktop - Google Drive Help](https://support.google.com/drive/answer/10838124?sjid=7721208110884477761-NA&visit_id=638192503824884459-786860809&rd=1)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.DRIVEDOCS.6.1v0.1 Instructions
To Disable Google Drive for Desktop:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu-\>Apps-\>Google Workspace-\>Drive and Docs-\>Google Drive for Desktop**.
3.  Uncheck the **Allow Google Drive for desktop in your organization box** checkbox
4.  Select **Save.**

To limit Google Drive for Desktop to authorized devices:

1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select Menu-\>Apps-\>Google Workspace-\>Drive and Docs-\>Features and Applications.
3.  Check the **Allow Google Drive for desktop in your organization box** checkbox
4.  Check the **Only allow Google Drive for desktop on authorized devices checkbox**.
5.  Ensure authorized devices are added to [company-owned inventory](https://support.google.com/a/answer/7129612?hl=en).
6.  Select Save.

Alternatively, [Context-Aware access policies](https://support.google.com/a/answer/9275380?hl=en) can be configured for more granular controls around authorized devices. The access level applied to Google Drive must have the "Apply to Google desktop and mobile apps" enabled to meet this requirement. For additional guidance, see the *Common Controls Minimum Viable Secure Baseline*, section "Context-Aware Access for All Devices that Connect to GWS SHOULD be Implemented."

## 7. DLP rules

This recommendation applies only to agencies that allow external sharing (see [Sharing Outside the Organization](#1-sharing-outside-the-organization)).

Using data loss prevention (DLP), you can create and apply rules to control the content that users can share in files outside the organization. DLP gives you control over what users can share and prevents unintended exposure of sensitive information.

DLP rules can use predefined content detectors to match PII (e.g., SSN), credentials (e.g., API keys), or specific document types (e.g., source code). Custom rules can also be applied based upon regex match or document labels.

### Policies

#### GWS.DRIVEDOCS.7.1v0.1
Agencies SHOULD configure DLP rules to block or warn on sharing files with sensitive data.

- _Rationale:_ Data Loss Prevention (DLP) rules help identify and limit the sharing of sensitive content, protecting agency information. By blocking and/or having warnings on these DLP-scanned files from being shared with users, the risk of unintentional introduction of sensitive content is significantly reduced.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [How to use predefined content detectors - Google Workspace Admin Help](https://support.google.com/a/answer/7047475#zippy=%2Cunited-states)
-   [Get started as a Drive labels admin - Google Workspace Admin Help](https://support.google.com/a/answer/9292382?hl=en)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.DRIVEDOCS.7.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Menu -\> Security -\> Access and data control -\> Data protection**.
3.  Click **Manage Rules**. Then click **Add rule** -\> **New rule** or click **Add rule** -\> **New rule from template**. For templates, select a template from the Templates page.
4.  In the **Name** section, add the name and description of the rule.
5.  In the **Scope** section, apply this rule only to the entire domain or to selected organizational units or groups, and click **Continue**. If there's a conflict between organizational units and groups in terms of inclusion or exclusion, the group takes precedence.
6.  In the **Apps** section, choose the trigger for **Google Drive, File created, modified, uploaded or shared**, and click **Continue**.
7.  In the **Conditions** section, click **Add Condition**.
8.  Configure appropriate content definition(s) based upon the agency's individual requirements and click **Continue**.
9.  Select the appropriate action to warn or block sharing, based upon the agency's individual requirements.
10. In the **Alerting** section, choose a severity level, and optionally, check **Send to alert center to trigger notifications**.
11. Review the rule details, mark the rule as **Active**, and click **Create.**
