# CISA Google Workspace Security Configuration Baseline for Common Controls

The Google Workspace (GWS) Admin console is the primary configuration hub for configuring and setting up the subscription. The scope of this document is to provide recommendations for setting up the subscription's security controls. This Secure Configuration Baseline (SCB) provides specific policies to strengthen the security of a GWS tenant.

The Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments. The SCuBA Secure Configuration Baselines (SCB) for Google Workspace (GWS) will help secure federal civilian executive branch (FCEB) information assets stored within GWS cloud environments through consistent, effective, modern, and manageable security configurations.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA.

This baseline is based on Google documentation and addresses the following:
- [Phishing-Resistant Multi-Factor Authentication](#1-phishing-resistant-multi-factor-authentication)
- [Context Aware Access](#2-context-aware-access)
- [Login Challenges](#3-login-challenges)
- [User Session Duration](#4-user-session-duration)
- [Secure Passwords](#5-secure-passwords)
- [Highly Privileged Accounts](#6-highly-privileged-accounts)
- [Conflicting Account Management](#7-conflicting-account-management)
- [Catastrophic Recovery Options](#8-catastrophic-recovery-options-for-super-admins)
- [GWS Advanced Protection Program](#9-gws-advanced-protection-program)
- [App Access to Google APIs](#10-app-access-to-google-apis)
- [Authorized Marketplace Apps](#11-authorized-google-marketplace-apps)
- [Google Takeout Service](#12-google-takeout-services-for-users)
- [System-Defined Rules](#13-system-defined-rules)
- [Google Workspace Logs](#14-google-workspace-logs)
- [Data Regions](#15-data-regions-and-storage)

## Assumptions

This document assumes the organization is using GWS Enterprise Plus. The Google Workspace (GWS) Common Controls Secure Configuration Baseline is unique among the GWS configuration baseline documents released by CISA in that it does not align to one specific GWS app. Implementers should be aware of this when cross-referencing the baseline statements to the live GWS admin console. Therefore, this document serves an enterprise-level compendium of implementable and testable configuration settings across the entire GWS admin console. The configurations specified herein correlate to the Security, Account, Directory, Rules, and Marketplace apps sections of the GWS admin console.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This Common Controls baseline document:

-   Assumes users are familiar with overarching Federal cyber guidance and cloud security fundamentals such as the shared responsibility model;
-   Accounts for recent direction from Executive Order 14028, the Federal Zero Trust Strategy (published as Office of Management & Budget Memo M-22-09 *Moving the U.S. Government Toward Zero Trust Cybersecurity Principles*), CISA's Zero Trust Maturity Model, and the Federal Cloud Security Technical Reference Architecture;
-   Observes industry guidance such as the Center for Internet Security's Google Workspace Foundations benchmark and Google official documentation and white papers; and
-   Was developed with input from both the Office of Management & Budget (OMB) and Google product managers and security engineers.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Phishing-Resistant Multi-Factor Authentication

Multi-factor authentication (MFA), particularly phishing-resistant MFA, is a critical security control against attacks such as password spraying, password theft, and phishing. Adopting phishing-resistant MFA may take time, especially on mobile devices. Organizations must upgrade to a phishing-resistant MFA method as soon as possible to be compliant with OMB M-22-09 and this policy to address the critical security threat posed by modern phishing attacks. In the intermediate period before phishing-resistant MFA is fully adopted, organizations should adopt an MFA method from the list in GWS.COMMONCONTROLS.1.4v0.1 below.

This control recognizes federation as a viable option for phishing-resistant MFA and includes architectural considerations around on-premises and cloud-native identity federation in established Federal Civilian Executive Branch (FCEB) environments. Federation for GWS can be implemented via a cloud-native identity provider (IdP). Google's documentation acknowledges that on-premises Active Directory implementations may be predominant in environments that adopt GWS and provides guidance on the use of Google Cloud Directory Sync (GCDS) to synchronize Google Account data with an established Microsoft Active Directory or LDAP server.

The following graphic illustrates the spectrum of MFA options and their relative strength, with phishing resistant MFA (per OMB Memo 22-09) being the mandated method.
Please note there is a distinction between Google 2 Step Verification (2SV) and MFA as a general term. While FIDO Security Key and Phone as a Security Key are acceptable forms of Phishing-Resistant MFA which rely on Google 2SV as the underlying mechanism, the other forms listed in the "strongest" column do not use Google
2SV but are still acceptable forms of Phishing-Resistant MFA.

<img src="/images/MFA.PNG">

### Policies

#### GWS.COMMONCONTROLS.1.1v0.1
Phishing-Resistant MFA SHALL be required for all users.


        > Phishing-resistant methods:

            - FIDO2 Security Key (directly in Google Workspace)

            - Phone as Security Key

            - FIDO2 Security Key (Federated from Identity Provider)

            - Federal Personal Identity Verification (PIV) card (Federated from agency Active Directory or other identity provider).

            - Google Passkeys

- _Rationale:_ Weaker forms of MFA do not protect against more sophisticated phishing attacks. By enforcing methods resistant to phishing, those risks are minimized. Additionally, phishing-resistant MFA is required for agency staff, contractors, and partners, by Office of Management and Budget Memo M-22-09.
- _Last modified:_ August 17, 2023
- _Note:_ Policy 1.1 applies if Phishing-Resistant MFA is available. Otherwise, Policy 1.4 applies.

- MITRE ATT&CK TTP Mapping
  - [T1621: MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

#### GWS.COMMONCONTROLS.1.2v0.1
Google 2SV new user enrollment period SHALL be set to 1 week.

- _Rationale:_ Enrollment must be enforced within a reasonable timeframe. 1 week balances the need for allowing new personnel time to set up their authentication methods and minimizing the risks inherent to not enforcing MFA immediately.
- _Last modified:_ August 17, 2023
- _Note:_ This setting and policy only applies when the means of Phishing-Resistant MFA in use relies
		on Google 2SV.

- MITRE ATT&CK TTP Mapping
  - [T1621: MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

#### GWS.COMMONCONTROLS.1.3v0.1
Allow users to trust the device SHALL be disabled.

- _Rationale:_ Trusting the device allows users to bypass 2-Step Verification for future logins on that device. Disabling device trusting makes it possible for future logins on the same device to be protected by MFA.
- _Last modified:_ August 17, 2023
- _Note:_ This setting and policy only applies when the means of Phishing-Resistant MFA in use relies
		on Google 2SV.

- MITRE ATT&CK TTP Mapping
  - [T1621: MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

#### GWS.COMMONCONTROLS.1.4v0.1
If phishing-resistant MFA is not yet tenable, an MFA method from the following list SHALL be used in the interim.

> Google prompt

> Google Authenticator

> Backup Codes

> Software Tokens One-Time Password (OTP): This option is commonly implemented using mobile phone authenticator apps

> Hardware Tokens OTP

- _Rationale:_ This is a stopgap security policy to help protect the organization if phishing-resistant MFA has not been enforced. This policy requires MFA enforcement, thus reducing single-form authentication risk. Additionally, this list excludes SMS and voice call, the weakest authentication methods, forcing users to use stronger MFA methods.
- _Last modified:_ August 17, 2023
- _Note:_ ONLY to be enforced if Policy 1.1 is not possible for the agency. SMS or Voice as the MFA method SHALL NOT be used.

- MITRE ATT&CK TTP Mapping
  - [T1621: MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Resources

-  [GWS Admin Help \| Set up 2-Step Verification (Deploy)](https://support.google.com/a/answer/9176657?hl=en&ref_topic=2759193&fl=1#zippy=%2Cchoose-a--step-verification-method-to-enforce%2Cturn-on-enforcement)
-   [GWS Admin Help \| Set up 2-Step Verification (Protect your business)](https://support.google.com/a/answer/175197#zippy=%2Csecurity-keys%2Cconsider-using-security-keys-in-your-business)
-   [GWS Admin Help \| Set up SSO via a third-party Identity provider](https://support.google.com/a/topic/7579248?hl=en&ref_topic=7556686)
-   [Google Cloud Architecture Center \| Federating Google Cloud with Active Directory](https://cloud.google.com/architecture/identity/federating-gcp-with-active-directory-introduction)
-   [Google Cloud Architecture Center \| Federating Google Cloud with Azure Active Directory](https://cloud.google.com/architecture/identity/federating-gcp-with-azure-active-directory)
-   [Google Workspace Updates /| Simplify and Strengthen Sign-In by Enabling Passkeys for Your Users](https://workspaceupdates.googleblog.com/2023/06/passkey-open-beta.html)
-   [Google Security Blog /| So Long Passwords, Thanks for all the Phish](https://security.googleblog.com/2023/05/so-long-passwords-thanks-for-all-phish.html)
-   [Allow Users to Skip Passwords at Sign-In (Beta)](https://support.google.com/a/answer/13529161)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   FIDO2-compliant security keys

### Implementation

Note: If using a third-party IdP with GWS, refer to Google documentation on [setting up third-party single sign-on](https://support.google.com/a/topic/7579248?hl=en&ref_topic=7556686) (SSO). If using GWS as the IdP, refer to [Google documentation on setting up SSO](https://support.google.com/a/answer/12032922?hl=en).

To enforce Phishing-Resistant 2-Step Verification (MFA) for all users, use the Google Workspace Admin Console:

#### Policy 1 common Instructions
1.  Sign in to [Google Admin console](https://admin.google.com/) as an administrator.
2.  Select **Security** -\> **Authentication.**
3.  Select **2-Step Verification.**

#### GWS.COMMONCONTROLS.1.1v0.1 Instructions
1.  Under **Authentication**, ensure that **Allow users to turn on 2-Step Verification** is checked.
2.  Set **Enforcement** to **On.**
3.  Under **Methods** select **Only security key.**
4.  Under **Security codes** select **Don't allow users to select security codes.**
5.  Select **Save**

#### GWS.COMMONCONTROLS.1.2v0.1 Instructions
1.  Set **New user enrollment** period to **1 Week**.
2.  Select **Save**

#### GWS.COMMONCONTROLS.1.3v0.1 Instructions
1.  Under Frequency, deselect the **Allow user to trust device** checkbox.
2.  Select **Save**

#### GWS.COMMONCONTROLS.1.4v0.1 Instructions

If using security keys:
1.  Under **Methods**, select **Only security Key**. Next, select **Don't allow users to select security codes**.
2.  Select **Save**

If security keys are not yet available for your organization:
1.  Under **Methods**, select **Any except verification codes via text, phone call**.
2.  Select **Save**

If using Passkeys, use the Google Workspace Admin Console:
1.  Sign in to [Google Admin console](https://admin.google.com/) as an administrator.
2.  Select **Security** -\> **Authentication** -\> **Passwordless.**
3.  Select **Skip passwords.**
4.  Select the **Allow users to skip passwords at sign-in by using passkeys** box.
5.  Select **Save.**

## 2. Context-aware Access

Device-based context-aware access provides access control policies based on device disposition attributes such as compliance with organizational secure configuration policies for devices (e.g., managed by Unified Endpoint Management). GWS also provides other context-aware access policies based on authentication and network information. These can be used to implement more targeted access policies. For advanced use cases, custom context aware access rules can be authored using the Common Expressions Language (CEL).

Device-based context-aware access can be used in several ways depending on agency business requirements. The following options are all acceptable approaches:

-   Properties of the device as reported by Google (encryption, screen lock, OS version, etc.)
-   Device inventory status (corporate-issued versus BYOD)
-   Use of Managed Chrome Browser
-   Data based on integration with certain third-party device management tools

It is extremely important to know how context-aware access policies affect one another, for example:

-   At a given scope (e.g., Organizational Unit [OU] or Group), each context aware access rule is evaluated separately. If any rule grants access, then access is allowed to the given application.
-   If rules are applied to OUs and Groups, which allow an action that may be denied after evaluating a policy at a higher level, then access will be allowed.

To enforce a device policy that requires company-owned devices, Google needs a list of serial numbers for company-owned devices.

### Policies

#### GWS.COMMONCONTROLS.2.1v0.1
Policies restricting access to GWS based on signals about enterprise devices SHOULD be implemented.

- _Rationale:_ Granular device access control afforded by context-aware access is in alignment with Federal zero trust strategy and principles. Context-aware access can help to increase the security of your GWS data by allowing you to restrict access to certain applications or services based on user/device attributes.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
    - [T1098:005: Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)

#### GWS.COMMONCONTROLS.2.2v0.1
Use of context-aware access for more granular controls, including using Advanced Mode (CEL), MAY be maximized and tailored if necessary.

- _Rationale:_ Unless you create and assign access levels, enabling context-aware access does not provide any additional protection. Context-aware access can help to increase the security of your GWS data by allowing you to restrict access to certain applications or services based on the user and/or device context. Advanced Mode's Common Expressions Language (CEL) gives administrators the ability to tailor access policies for devices, time-based use cases, authentication, and to combine multiple conditions into tailored controls.
- _Last modified:_ July 11, 2023

- MITRE ATT&CK TTP Mapping
  - [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
    - [T1098:005: Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)

### Resources

-   [GWS Admin Help \| Context-Aware Access overview](https://support.google.com/a/answer/9275380)
-   [GWS Admin Help \| Context-Aware Access examples for Basic mode](https://support.google.com/a/answer/9587667)
-   [GWS Admin Help \| Context-Aware Access examples for Advanced mode](https://support.google.com/a/answer/11368990)
-   [GWS Admin Help \| Device management security checklist](https://support.google.com/a/answer/7422256)
-   [GWS Admin Help \| Set up guide: Deploy company-owned devices in Google endpoint management](https://support.google.com/a/answer/10287358)
-   [GWS Admin Help \| Turn endpoint verification on or off](https://support.google.com/a/answer/9007320)
-   [GWS Admin Help \| Set up guide: Deploy company-owned devices in Google endpoint management—Steps 1 and 2](https://support.google.com/a/answer/10287358#zippy=%2Cstep-sign-up-for-enterprise-management-services%2Cstep-source-devices)
-   [GitHub \| Google \| Google Common Expressions Language (CEL)](https://github.com/google/cel-spec)
-   [Google Cloud Access Context Manager \| Macros for CEL expressions](https://cloud.google.com/access-context-manager/docs/custom-access-level-spec#macros_for_cel_expressions)
-   [Google Cloud Access Context Manager \| Custom access level specification](https://cloud.google.com/access-context-manager/docs/custom-access-level-spec)
-   [GWS Blog \| Enable advanced context-aware access to Google Workspace in the Admin console](https://workspaceupdates.googleblog.com/2021/11/enable-advanced-context-aware-access-to.html)
-  [GWS Admin Help \| Google Workspace Device management security checklist](https://support.google.com/a/answer/7422256)
-   [GWS Admin Help \| Deploy Context-Aware Access](https://support.google.com/a/answer/12643733)

### Prerequisites

-   One or more of the following user roles should have been configured to set context-aware policies:

        > Super admin

        > Delegated admin with each of these privileges:

                - Data Security -\> Access level management

                - Data Security -\> Rule management

                - Admin API Privileges -\> Groups\>Read

                - Admin API Privileges -\> Users\>Read

-   Serial numbers may be required to enforce a policy for company-owned devices. Refer to [Google documentation](https://support.google.com/a/answer/10287358) on device management for additional guidance.

### Implementation

#### GWS.COMMONCONTROLS.2.1v0.1 Instructions
To turn on Context-Aware Access:

1.  Access the [Google Admin console](https://admin.google.com/).
2.  From the menu, go to **Security** -\> **Access and data control** -\> **Context-Aware Access**.
3.  Verify **Context-Aware Access** is **ON for everyone**. If not, click **Turn On**.

#### GWS.COMMONCONTROLS.2.2v0.1 Instructions
Note that the implementation details of context-aware access use cases will vary per agency. Refer to [Google's documentation](https://support.google.com/a/answer/12643733) on implementing context-aware access for your specific use cases. Common use cases include:

-   Require company-owned on desktop but not on mobile device
-   Require basic device security
-   Allow access to contractors only through the corporate network
-   Block access from known hijacker IP addresses
-   Allow or disallow access from specific locations
-   Use nested access levels instead of selecting multiple access levels during assignment

## 3. Login Challenges

Login challenges are additional security measures used to verify a user's identity. For example, Google might ask the user to confirm their recovery email before logging in as part of a challenge.

### Policies

#### GWS.COMMONCONTROLS.3.1v0.1
Login Challenges SHALL be enabled when third party SAML SSO is in use.

- _Rationale:_ Without enabling Post-SSO verification, any Google 2-Step Verification (2SV) configuration is ignored for third-party SSO users. By enabling Post-SSO verification, 2SV verification policies will applied.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

### Resources

-   [GWS Admin Help \| Protect Google Workspace accounts with security challenges](https://support.google.com/a/answer/6002699)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   When using Employee ID challenge, the Employee ID must be uploaded to Google Workspace through the Agency's Identity Management infrastructure (e.g., via GCDS).

### Implementation

#### GWS.COMMONCONTROLS.3.1v0.1 Instructions
1.  Sign in to [Google Admin console](https://admin.google.com) as an administrator.
2.  Select **Security**-\>**Authentication**-\>**Login challenges.**
3.  Under **Organizational units**, ensure that the name for the entire organization is selected.
4.  Click **Post-SSO verification**, then select **Ask users for additional verifications from Google if a sign-in looks suspicious, and always apply 2-Step Verification policies (if configured)**. Click **SAVE**.
5.  Optionally, if employee IDs are known to agency employees (or accessible to the employee outside of Google Workspace), they may be used.
6.  Click **Login challenges**.
7.  Select the **Use employee ID to keep my users more secure** checkbox.
8.  Click **SAVE**.

## 4. User Session Duration

This control allows configuring of limits on how long a GWS session can be active before being prompted for authentication credentials.

Note: If using a third-party IdP, and agency-set web session lengths for its users, then there will be a need to set the IdP session length parameter to expire before the Google session expires to ensure users are forced to sign in again. See [GWS documentation](https://support.google.com/a/answer/7576830) for additional details.

### Policies

#### GWS.COMMONCONTROLS.4.1v0.1
Users SHALL be forced to re-authenticate after an established 12-hour GWS login session has expired.

- _Rationale:_ Allowing sessions to persist indefinitely allows users to bypass 2-Step Verification for future activity on that device. Limiting sessions to 12 hours may reduce the impact of session hijacking attacks and prevent users from inadvertently remaining logged in on unattended devices.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1550: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
    - [T1550:004: Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
  - [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
    - [T1078:004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

### Resources

-   [GWS Admin Help \| Set session length for Google services](https://support.google.com/a/answer/7576830?hl=en)

### Prerequisites

-   None

### Implementation

#### GWS.COMMONCONTROLS.4.1v0.1 Instructions
To configure Google session control:

1.  Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.  Select **Security.**
3.  Select **Access and data control** -\> **Google session control.**
4.  Look for the **Web session duration** heading.
5.  Set the duration to **12 hours.**

## 5. Secure Passwords

Per NIST 800-63 and OMB M-22-09, ensure that user passwords do not expire and that long passwords are chosen. Research indicates that frequent password rotation breeds poor password choice and encourages password reuse. Ensure that passwords are strong to defend against brute-force attacks. Ensure that passwords are not reused to defend against credential theft.

### Policies

#### GWS.COMMONCONTROLS.5.1v0.1
User password strength SHALL be enforced.

- _Rationale:_ Weak passwords increase the risk of account compromise. Enforcing password strength adds an additional layer of defense, reducing the risk of account compromise.
 Strong password policies protect an organization by prohibiting the use of weak passwords.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

#### GWS.COMMONCONTROLS.5.2v0.1
User password length SHALL be at least 12 characters.

- _Rationale:_ The National Institute of Standards and Technology (NIST) has published guidance indicating that password length is a primary factor in characterizing password strength (NIST SP 800-63B). Longer passwords tend to be more resistant to brute force and dictionary-based attacks.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

#### GWS.COMMONCONTROLS.5.3v0.1
Password policy SHALL be enforced at next sign-in.

- _Rationale:_ Unless the password policy is enforced at next login, a user could potentially operate indefinitely using a weak password. Enforcing the policy at next login ensures that all active user passwords meet current requirements.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

#### GWS.COMMONCONTROLS.5.4v0.1
User passwords SHALL NOT be reused.

- _Rationale:_ Password reuse represents a significant security risk. Preventing password reuse when possible limits the scope of a compromised password.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

#### GWS.COMMONCONTROLS.5.5v0.1
User passwords SHALL NOT expire.

- _Rationale:_ The National Institute of Standards and Technology (NIST), OMB, and Microsoft have published guidance indicating mandated periodic password changes make user accounts less secure. For example, OMB M-22-09 states, "Password policies must not require use of special characters or regular rotation."
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

### Resources

-   [GWS Admin Help \| Enforce and monitor password requirements for users](https://support.google.com/a/answer/139399?hl=en#zippy=%2Cwhat-makes-a-password-strong)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

To configure a strong password policy is configured, use the Google Workspace Admin Console:

#### Policy Group 5 common Instructions
1.  Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.  Select **Security** -\> **Authentication.**
3.  Locate **Password management.**
4. Follow implementation for each individual policy.
5. Select **Save**.

#### GWS.COMMONCONTROLS.5.1v0.1 Instructions
1.  Under **Strength**, select the **Enforce strong password** checkbox.

#### GWS.COMMONCONTROLS.5.2v0.1 Instructions
1.  Under **Length**, set **Minimum Length** to 12+.

#### GWS.COMMONCONTROLS.5.3v0.1 Instructions
1.  Under **Strength and Length enforcement**, select the **Enforce password policy at next sign-in** checkbox.

#### GWS.COMMONCONTROLS.5.4v0.1 Instructions
1.  Under **Reuse**, deselect the **Allow password reuse** checkbox.

#### GWS.COMMONCONTROLS.5.5v0.1 Instructions
1.  Under **Expiration**, select **Never Expires.**

## 6. Highly Privileged Accounts

Highly privileged accounts represent significant risk to an agency if compromised or if insiders use them in an unauthorized way. Highly privileged accounts share the same risk factors related to the catastrophic impacts on GWS services, user community and agency data, if compromised. This section supports the definition of highly privileged accounts and the controls necessary to protect them.

Pre-Built GWS Admin Roles considered highly privileged:

-   Super Admin: This role possesses critical control over the entire GWS structure. It has access to all features in the Admin Console and Admin API and can manage every aspect of agency GWS accounts.
-   User Management Admin: This account has rights to add, remove, and delete normal users in addition to managing all user passwords, security settings, and other management tasks that make it potentially crucial if compromised.
-   Services Admin: This admin has full rights to turn on or off GWS services and security settings for these services (Gmail, Drive, Voice, etc.). Given that most GWS features are premised on these services being secure, compromise of this account would be critical.
-   Mobile Admin: This admin has full rights to manage all the agency mobile devices including authorizing their use and controlling the apps that can be downloaded and used on them. This admin can also set the security policies on all agency mobile devices connected to GWS.
-   Groups Admin: This admin has full rights to view profiles in the organizational and OU structures and can manage all rights for those members in the group.

### Policies

#### GWS.COMMONCONTROLS.6.1v0.1
All highly privileged accounts SHALL leverage Google Account authentication with phishing-resistant MFA and not the agency's authoritative on-premises or federated identity system.

- _Rationale:_ By provisioning cloud-only accounts to privileged users, the risks associated with a compromise of on-premises federation infrastructure are reduced. This makes it is more challenging for an adversary to pivot from a compromised on-premises environment to the cloud with privileged access.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)

#### GWS.COMMONCONTROLS.6.2v0.1
A minimum of **two** and maximum of **four** separate and distinct super admin users SHALL be configured.

- _Rationale:_ The super admin role provides unfettered access to the workspace. Properly managing the number of users with this level of access makes workspace compromise more challenging. However, having too few accounts can be problematic as it increases the risk of losing admin access entirely (e.g., if a super admin forgets their password); having between 2 and 4 balances these two concerns.
- _Last modified:_ July 10, 2023
- _Note:_ Admin count does not include "break-glass" super admin accounts.


- MITRE ATT&CK TTP Mapping
  - [T1136: Create Account](https://attack.mitre.org/techniques/T1136/)
    - [T1136:003: Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)
  - [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
    - [T1098:003: Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

### Resources

-   [Google Cloud Architecture Center \| Best practices for planning accounts and organizations](https://cloud.google.com/architecture/identity/best-practices-for-planning)
-   [GWS Admin Help \| Create, edit, and delete custom admin roles](https://support.google.com/a/answer/2406043)
-   [GWA Admin Help \| Assign Specific Admin Roles](https://support.google.com/a/answer/9807615?hl=en)
-   [GWA Admin Help \| Pre-Built Admin Roles](https://support.google.com/a/answer/2405986?hl=en)

### Prerequisites

-   Super admin users cannot log in to admin.google.com with a 3rd party IdP when using super admin level accounts—they must use Google Login as the authentication mechanism. This policy extends this rule to other admin types.
-   Delegated accounts, including the ones defined as highly privileged above, can by default, use a third-party IdP to access admin.google.com: however, this policy prohibits that practice. All highly privileged accounts must use phishing resistant Google Authentication.

### Implementation

#### GWS.COMMONCONTROLS.6.1v0.1 Instructions
1.  The implementation process for this can be located [here](https://support.google.com/a/answer/9807615).

#### GWS.COMMONCONTROLS.6.2v0.1 Instructions
To obtain a list of all GWS Super Admins:

1.  Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.  Navigate to **Account** -\> **Admin Roles**.
3.  Click the **Super Admin** role in the list of roles
4.  The subsequent dialog provides a list of Super Admins.

## 7. Conflicting Account Management

It is possible for employees of an organization to create conflicting, unmanaged accounts that are unmanaged by an enterprise's Google Workspace tenant. Unmanaged accounts are defined as users who independently created a Google account using the organization's domain. For example, a user with an enterprise/corporate email of user@company.com could create a personal, unmanaged Google account using that email address. This would create an account conflict in a GWS tenant licensed to company.com since email addresses are unique.

Creating a conflicting account can also happen unintentionally. After signing up for Google Cloud Identity or Google Workspace, admins might decide to set up single sign-on with an external identity provider (IdP) such as Azure Active Directory (AD) or Active Directory. When configured, the external IdP might automatically create accounts in Cloud Identity or Google Workspace for all users for which single sign-on was enabled, inadvertently creating conflicting accounts.

Unmanaged accounts carry significant risk, as they cannot be managed by admins, rendering them outside of the scope of protection admins can apply to keep work data secure. Significantly, two-step verification (2SV) cannot be enforced. Even if access is revoked, these accounts can carry a social engineering risk. Further, reconciling conflicting accounts creates churn for admins and adds to the workload of onboarding users to Google Workspace & Google Cloud.

The GWS admin console provides several administrative options for handling conflicting, unmanaged accounts:
  - Automatically invite users to transfer unmanaged accounts.
  - Replace unmanaged accounts with managed ones.
  - Don't create new accounts if unmanaged accounts exist.

This policy requires replacing unmanaged accounts with managed ones. When this option is configured, data owned by the account will not be imported; the user will receive a temporary account address, which they'll need to manually replace with a @gmail.com address of their choice; the user will receive an email notification of this and are informed they cannot use the original email any longer.

By changing the email address, the user resolves the conflict by ensuring that the managed account and consumer account have different identities. The result remains that they have one consumer account that has all their original data, and one managed account that doesn't have access to the original data.

### Policies

#### GWS.COMMONCONTROLS.7.1v0.1
Account conflict management SHALL be configured to replace conflicting unmanaged accounts with managed ones.

- _Rationale:_ Unmanaged user accounts cannot be controlled or monitored by workspace admins. By resolving conflicting accounts, you ensure all users in your workspace are using managed accounts.
- _Last modified:_ September 14, 2023

- MITRE ATT&CK TTP Mapping
  - [T1136: Create Account](https://attack.mitre.org/techniques/T1136/)
    - [T1136:003: Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)
  - [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
    - [T1098:003: Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
  - [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)

### Resources

-   [GWS Admin Help | Use the transfer tool to migrate unmanaged users](https://support.google.com/a/answer/6178640)
-   [GWS Admin Help | Find and add unmanaged users](https://support.google.com/a/answer/11112794)
-   [Google Workspace Updates Blog | Resolve conflict accounts faster with the new Conflict Accounts Management tool](https://workspaceupdates.googleblog.com/2023/08/conflict-accounts-management-tool.html)
-   [Google Cloud Architecture Center | Migrating consumer accounts](https://cloud.google.com/architecture/identity/migrating-consumer-accounts#using_a_conflicting_account)
-   [Google Cloud Architecture Center | Best practices for planning accounts and organizations](https://cloud.google.com/architecture/identity/best-practices-for-planning)

### Prerequisites

-   Super Admin privileges

### Implementation
#### GWS.COMMONCONTROLS.7.1v0.1 Instructions

To configure account conflict management per the policy:
1.	Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.	Navigate to **Account** -\> **Account settings.**
3.	Click the **Conflicting accounts management** card.
4.	Select the radio button option: **"Replace conflicting unmanaged accounts with managed ones."**
5.	Click **Save.**

## 8. Catastrophic Recovery Options for Super Admins

This section covers the admin self-recovery setting that is in Google Admin console.

### Policies

#### GWS.COMMONCONTROLS.8.1v0.1
Account self-recovery for Super Admins SHALL be disabled

- _Rationale:_ If enabled, an adversary could attempt to gain access to a super admin account through the account recovery method. By disabling this feature, super admins are forced to contact another super admin to recover their account, making it more difficult for a potential adversary to compromise their account.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)

### Resources

-   [GWS Admin Help \| Allow super administrators to recover their password](https://support.google.com/a/answer/9436964?fl=1)
-   [GWS Admin Help \| Recover an account protected by 2-Step Verification](https://support.google.com/a/answer/9176734?hl=en)

### Prerequisites

-   None

### Implementation

#### GWS.COMMONCONTROLS.8.1v0.1 Instructions
To disable Super Admin account self-recovery:

1.  Sign in to https://admin.google.com as an administrator.
2.  Select **Security** -\> **Authentication.**
3.  Select **Account Recovery**.
4.  Click **Super admin account recovery**.
5.  To apply the setting to all your Super Admins, leave the top OU selected. Otherwise, select a child OU or a configuration group.
6.  Deselect the **Allow Super Admins to recover their account** checkbox.
7.  Click **Save**.
8.  Ask your Super Admins to set up a recovery phone number or email address for receiving password recovery instructions.

## 9. GWS Advanced Protection Program

This control enforces more secure protection of highly privileged, senior executive and sensitive users accounts from targeted attacks. It enforces optional GWS user security features like:

-   Strong authentication with security keys
-   Use of security codes with security keys
-   Restrictions on third-party access to account data
-   Deep Gmail scans
-   Google Safe Browsing protections in Chrome
-   Account recovery through admin

### Policies

#### GWS.COMMONCONTROLS.9.1v0.1
Highly privileged accounts SHALL be enrolled in the GWS Advanced Protection Program.

- _Rationale:_ Sophisticated phishing tactics can trick even the most savvy users into giving their sign-in credentials to attackers. Advanced Protection requires you to use a security key, which is a hardware device or special software on your phone used to verify your identity, to sign in to your Google Account. Unauthorized users won't be able to sign in without your security key, even if they have your username and password. The Advanced Protection Program includes a curated group of high-security policies that are applied to enrolled accounts. Additional policies may be added to the Advanced Protection Program to ensure the protections are current.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)

#### GWS.COMMONCONTROLS.9.2v0.1
All sensitive user accounts SHOULD be enrolled into the GWS Advanced Protection Program.

- _Rationale:_ Sophisticated phishing tactics can trick even the most savvy users into giving their sign-in credentials to attackers. Advanced Protection requires you to use a security key, which is a hardware device or special software on your phone used to verify your identity, to sign in to your Google Account. Unauthorized users won't be able to sign in without your security key, even if they have your username and password. The Advanced Protection Program includes a curated group of high-security policies that are applied to enrolled accounts. Additional policies may be added to the Advanced Protection Program to ensure the protections are current.
- _Last modified:_ July 10, 2023
- _Note:_ This control enforces more secure protection of sensitive user accounts from targeted attacks. Sensitive user accounts include political appointees, Senior Executive Service (SES) officials, or other senior officials whose account compromise would pose a level of risk prohibitive to agency mission fulfillment

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1556: Modifying Authentication Process](https://attack.mitre.org/techniques/T1556/)
    - [T1556:006: Modifying Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)

### Resources

-   [GWS Admin Help \| Protect users with the Advanced Protection Program](https://support.google.com/a/answer/9378686)
-   [GWS Admin Help \| Advanced Protection Program FAQ](https://support.google.com/a/answer/9503534?hl=en)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   Two security keys are required for added assurance. If one key is lost or damaged, users can use the second key to regain account access.

### Implementation

#### Policy Group 9 Instructions
To allow all users to enroll:

1.  Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.  Select **Security -**\> **Authentication** -\> **Advanced Protection Program.**
3.  On the right, locate the **Advanced Protection** header.
4.  Locate the **Allow users to enroll in the Advanced Protection Program** header.
5.  Select **Enable user enrollment.**
6.  Click **SAVE.**

## 10. App Access to Google APIs

Agencies need to have a process in place to manage and control application access to GWS data. This control enables the ability to restrict access to Google Workspace APIs from other applications and is aimed at mitigating the significant cybersecurity risk posed by the potential compromise of OAuth tokens. The baseline policy statements are written to allow implementers to balance operational need with risk posed by granting app access.

### Policies

#### GWS.COMMONCONTROLS.10.1v0.1
Agencies SHALL develop and implement a process to explicitly allow-list (trust) third-party app access to GWS services.

- _Rationale:_ Third-party apps may include malicious content. Developing a process to review and approve apps reduces the risk of allowing malicious apps to connect to the workspace.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1550: Use Alternate Authentication Materials](https://attack.mitre.org/techniques/T1550/)
    - [T1550:001: Use Alternate Authentication Materials: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:002: Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

#### GWS.COMMONCONTROLS.10.2v0.1
Agencies SHALL use GWS application access control policies to restrict access to all GWS services by third party apps.

- _Rationale:_ Third-party apps may include malicious content. Restricting app access to only apps trusted by the agency reduces the risk of allowing malicious apps to connect to the workspace.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1550: Use Alternate Authentication Materials](https://attack.mitre.org/techniques/T1550/)
    - [T1550:001: Use Alternate Authentication Materials: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:002: Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

#### GWS.COMMONCONTROLS.10.3v0.1
Agencies SHALL NOT allow users to consent to access to low-risk scopes.

- _Rationale:_ Allowing users to give access to OAuth scopes that aren't classified as high-risk could still allow for apps that are not trusted to be granted access by non-administrator personnel and without having to be allowlisted in accordance with policy 10.1.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1550: Use Alternate Authentication Materials](https://attack.mitre.org/techniques/T1550/)
    - [T1550:001: Use Alternate Authentication Materials: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:002: Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

#### GWS.COMMONCONTROLS.10.4v0.1
Agencies SHALL NOT trust unconfigured internal apps.

- _Rationale:_ Internal apps may contain vulnerabilities or even malicious content created by compromised user accounts. Restricting access to these apps reduces the risk of allowing unsafe apps to connect to the workspace.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1550: Use Alternate Authentication Materials](https://attack.mitre.org/techniques/T1550/)
    - [T1550:001: Use Alternate Authentication Materials: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:002: Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

#### GWS.COMMONCONTROLS.10.5v0.1
Agencies SHALL NOT allow users to access unconfigured third-party apps.

- _Rationale:_ External apps may contain vulnerabilities and malicious content. Restricting access to these apps reduces the risk of allowing unsafe apps to connect to the workspace.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1550: Use Alternate Authentication Materials](https://attack.mitre.org/techniques/T1550/)
    - [T1550:001: Use Alternate Authentication Materials: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:002: Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)


### Resources

-   [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819)
-   [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
-   [OMB M-22-09](https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf)
-   [GWS Admin Help \| Control which third-party & internal apps access GWS data](https://support.google.com/a/answer/7281227#zippy=%2Cstep-control-api-access%2Cstep-restrict-or-unrestrict-google-services%2Cbefore-you-begin-review-authorized-third-party-apps%2Cstep-manage-third-party-app-access-to-google-services-add-apps)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### Policy Group 10 Instructions
1.  Sign in to [Google Admin console](https://admin.google.com).
2.  Go to **Security** -\> **Access and Data Control** -\> **API controls.**

#### GWS.COMMONCONTROLS.10.1v0.1 instructions:
1.  There are no implementation steps for this policy

#### GWS.COMMONCONTROLS.10.2v0.1 instructions:
1.  Select **Manage Google Services.**
2.  Select the **Services box** to check all services boxes.
3.  Once this box is selected, then the **Change access** link at the top of console will be available; select it.
4.  Select **Restricted: Only trusted apps can access a service.**
5.  Select **Change** then **confirm** if prompted.

#### GWS.COMMONCONTROLS.10.3v0.1 instructions:
1.  Select **Manage Google Services.**
2.  Select the **Services box** to check all services boxes.
3.  Once this box is selected, then the **Change access** link at the top of console will be available; select it.
4.  Ensure to uncheck the check box next to **For apps that are not trusted, allow users to give access to OAuth scopes that aren't classified as high-risk.**
5.  Select **Change** then **confirm** if prompted.

#### GWS.COMMONCONTROLS.10.4v0.1 Instructions
1.  Select **Settings.**
2.  Select **Internal apps** and uncheck the box next to **Trust internal apps.**
3.  Select **SAVE.**

#### GWS.COMMONCONTROLS.10.5v0.1 Instructions
1.  Select **Settings.**
2.  Select **Unconfigured third-party apps** and select **Don't allow users to access any third-party apps**
3.  Select **SAVE.**

It should be noted that admins will have to manually approve each trusted app. The implementation steps for this activity are outlined in Google's [documentation on controlling which third-party & internal apps access GWS data](https://support.google.com/a/answer/7281227) (also listed under Resources).


## 11. Authorized Google Marketplace Apps

This section enables the ability to restrict the installation of Google Workspace Marketplace apps to a defined list provided and configured in the app allowlist. This guidance includes and applies to internally developed applications. This control disables legacy authentication and requires the use of modern authentication protocols based on federation for access from applications.

Some older versions of common software may break when this control is implemented. Examples of these apps include:
-   Mails configured with POP3
-   Older versions of Outlook

### Policies

#### GWS.COMMONCONTROLS.11.1v0.1
Only approved Google Workspace Marketplace applications SHOULD be allowed for installation.

- _Rationale:_ Marketplace apps may include malicious content. Restricting app access to only apps trusted by the agency reduces the risk of allowing malicious apps to connect to the workspace.
- _Last modified:_ October 24, 2023

- MITRE ATT&CK TTP Mapping
  - [T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    - [T1195:002: Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)

#### GWS.COMMONCONTROLS.11.2v0.1
Access to Google Workspace applications by less secure apps that do not meet security standards for authentication SHALL be prevented.

- _Rationale:_ Antiquated authentication methods introduce additional risk into the workspace environment. Only allowing apps that use modern authentication standards helps reduce the risk of credential compromise.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
    - [T1110:001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
    - [T1110:002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)
    - [T1110:003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Resources

-   [GWS Admin Help \| Manage Google Workspace Marketplace apps on your allowlist](https://support.google.com/a/answer/6089179?fl=1)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)
-   [GWS Admin Help \| Control access to less secure apps](https://support.google.com/a/answer/6260879?hl=en)

### Prerequisites

-   None

### Implementation

#### GWS.COMMONCONTROLS.11.1v0.1 Instructions
1.  Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.  Select **Apps** -\> **Google Workspace Marketplace apps** -\> **Settings.**
3.  Select **Allow users to install and run allowlisted apps from the Marketplace.**
4.  Ensure that the **Allow exception for internal apps. Users can install and run any internal app, even if it is not allowlisted.** checkbox is unchecked.
5.  Click **Save.**

To add an app to the allowlist:
1.  On the left-hand side above **Setting,** click **Apps lists.**
2.  Click the **ALLOWLIST APP** to add an app to the allow list.

    or

3.  Click **Allowlisted Apps** to manage the allow list.

#### GWS.COMMONCONTROLS.11.2v0.1 Instructions
1.  Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.  Select **Security.**
3.  Select **Access and data control** -\> **Less secure apps.**
4.  Select **Disable access to less secure apps (Recommended).**
5.  Click **Save** to commit this configuration change.

## 12. Google Takeout Services for Users

This section prevents users from downloading a copy of the Google Takeout service's data to their user accounts. Services include Google Blogger, Books, Maps, Pay, Photos, Play, Play Console, Location History and YouTube, among numerous others.

### Policies

#### GWS.COMMONCONTROLS.12.1v0.1
Google Takeout services SHALL be disabled.

- _Rationale:_ Google Takeout is a service that allows you to download a copy of your data stored within 40+ Google products and services, including data from Gmail, Drive, Photos, and Calendar. While there may be a valid use case for individuals to back up their data in non-enterprise settings, this feature represents considerable attack surface as a mass data exfiltration mechanism, particularly in enterprise settings where other backup mechanisms are likely in use.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [GWS Admin Help \| Security checklist for medium and large businesses](https://support.google.com/a/answer/7587183?hl=en#zippy=%2Caccounts%2Capps-google-workspace-only%2Csites-google-workspace-only%2Cdrive%2Cgoogle-groups)
-   [GWS Admin Help \| Allow or block Google Takeout](https://support.google.com/a/answer/6396995#managing&zippy=)

### Prerequisites

-   Determine which OU or access group will be affected by this policy and confirm that the right user and system accounts are in that OU or access group.

### Implementation

#### GWS.COMMONCONTROLS.12.1v0.1 Instructions
1.  Sign in to https://admin.google.com as an administrator.
2.  Select **Account** then **Google Takeout.**
3.  Select **User access to Takeout for Google services**.
4.  For services without an individual admin control, select **Services without an individual admin control** then **Edit.**
5.  Select **Don't allow for everyone**.
6.  Click **Save**.
7.  For services with an individual admin control, under **apps** select the checkbox next to **Service name** and select **Don't allow**.
8.  Click **Save.**

## 13. System-defined Rules

GWS includes system-defined alerting rules that provide situational awareness into risky events and actions. A security best practice is to enable the following list of rules. Please note that some, but not all, of these rules may be set to "on" by default. Rules that are not listed may be useful but not security relevant. Review all system-defined rules to implement the appropriate configuration based on individual requirements.

-   Google security checklist for medium and large businesses
-   Government-backed attacks
-   User-reported phishing
-   User's Admin privilege revoked
-   User suspended for spamming through relay
-   User suspended for spamming
-   User suspended due to suspicious activity
-   User suspended (Google identity alert)
-   User suspended (by admin)
-   User granted Admin privilege
-   User deleted
-   Suspicious programmatic login
-   Suspicious message reported
-   Suspicious login
-   Suspicious device activity
-   Suspended user made active
-   Spike in user-reported spam
-   Rate limited recipient
-   Phishing message detected post-delivery
-   Phishing in inboxes due to bad allowlist
-   New user added
-   Mobile settings changed
-   Malware message detected post-delivery
-   Leaked password
-   Google Operations
-   Gmail potential employee spoofing
-   Email settings changed
-   Drive settings changed
-   Domain data export initiated
-   Device compromised
-   Calendar settings changed
-   Account suspension warning
-   Client-side encryption service unavailable

### Policies

#### GWS.COMMONCONTROLS.13.1v0.1
Required system-defined alerting rules, as listed in the Policy group description, SHALL be enabled with alerts.

- _Rationale:_ Potentially malicious or service-impacting events may go undetected without a means of detecting these events. Setting up a mechanism to alert administrators to the list of events linked above draws attention to them to minimize any impact to users and the agency.
- _Last modified:_ July 10, 2023
- _Note:_ Any system-defined rules not listed are considered optional but should be reviewed and considered for activation by an administrator.

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

### Resources

-   [GWS Admin Help \| Data sources for the security investigation tool](https://support.google.com/a/answer/11482175)
-   [GWS Admin Help \| View and edit system-defined rules](https://support.google.com/a/answer/3230421)

### Prerequisites

-   None

### Implementation

#### GWS.COMMONCONTROLS.13.1v0.1 Instructions
1.  Sign in to [Google Admin console](https://admin.google.com).
2.  On the left navigation pane, click the hamburger menu above **Home**-\>**Show more**.
3.  Click **Rules**.
4.  From the Rules page, click **Add a filter**.
5.  From the drop-down menu, select **Type**.
6.  Select the **System defined** check box.
7.  Click **Apply**.
8.  A list of system defined rules displays. Select one of the rules from the list by clicking the table row for that rule—for example, the Device compromised rule.
9.  From the Rule details page, you can view the conditions and actions for the rule—for example, to confirm if email notifications are turned on, and to confirm the recipients for those email notifications.
10. Click **Edit Rule**.
11. Click **Next: View Conditions**.
12. Click **Next: Add Actions**.
13. From the Actions page, you can change the severity for the alert to High, Medium, or Low, send an alert to the alert center if the rule's conditions are met, set up admin email notifications, and specify recipients for those notifications.
14. Click **Next: Review**.
15. Review the updated rule details, and then click **Update Rule**.

## 14. Google Workspace Logs

Configure GWS to send critical logs to the agency's centralized Security Information and Event Management (SIEM) so that they can be audited and queried. Configure GWS to send logs to a storage account and retain them for when incident response is needed.

### Policy

#### GWS.COMMONCONTROLS.14.1v0.1
The following critical logs SHALL be sent to the agency's centralized SIEM.

        > Admin Audit logs

        > Enterprise Groups Audit logs

        > Login Audit logs

        > OAuth Token Audit logs

        > SAML Audit log

        > Context Aware Access logs

- _Rationale:_ This policy ensures enhanced security by centralizing critical logs in the agency's Security Information and Event Management (SIEM) system, enabling timely detection and response to potential security incidents. It also aids in regulatory compliance, maintaining the confidentiality, integrity, and availability of the agency's information systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:008: Impair Defenses: Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)

#### GWS.COMMONCONTROLS.14.2v0.1
Audit logs SHALL be maintained for at least 6 months in active storage and an additional 18 months in cold storage, as dictated by OMB M-21-31.

- _Rationale:_ Audit logs may no longer be available when needed if they are not retained for a sufficient time. Increased log retention time gives an agency the necessary visibility to investigate incidents that occurred some time ago.
- _Last modified:_ January 30, 2024

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:008: Impair Defenses: Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)

### Resources

-   [GWS Admin Help \| Share data with Google Cloud Platform services](https://support.google.com/a/answer/9320190)
-   [Google Cloud Operations Suite \| Audit logs for Google Workspace](https://cloud.google.com/logging/docs/audit/gsuite-audit-logging)
-   [Google Cloud Operations Suite \| View and manage audit logs for Google Workspace](https://cloud.google.com/logging/docs/audit/configure-gsuite-audit-logs)
-   [Google Cloud Operations Suite \| Aggregate and store your organization's logs](https://cloud.google.com/logging/docs/central-log-storage)
-   [Google Cloud Architecture Center \| Google Logging export scenarios](https://cloud.google.com/architecture/design-patterns-for-exporting-stackdriver-logging?hl=en#logging_export_scenarios)
-   [GWS Admin Help \| Data sources for GWS Audit and investigation page](https://support.google.com/a/answer/9725452)
-   [Google Cloud Operations Suite \| Configure and Manage sinks – Google Cloud](https://cloud.google.com/logging/docs/export/configure_export_v2)
-   [OMB M-21-31 \| Office of Management and Budget](https://www.whitehouse.gov/wp-content/uploads/2021/08/M-21-31-Improving-the-Federal-Governments-Investigative-and-Remediation-Capabilities-Related-to-Cybersecurity-Incidents.pdf)

### Prerequisites

-   None

### Implementation

#### GWS.COMMONCONTROLS.14.1v0.1 Instructions
Follow the configuration instructions unique to the products and integration patterns at your organization to send the security logs to the security operations center for monitoring.

Note: Agencies can benefit from security detection capabilities offered by the CISA Cloud Log Aggregation Warehouse (CLAW) system. Agencies are urged to send the logs to CLAW. Contact CISA at [cyberliason@cisa.dhs.gov](mailto:cyberliason@cisa.dhs.gov) to request integration instructions.

#### GWS.COMMONCONTROLS.14.2v0.1 Instructions
1.  There is no implementation for this policy.

## 15. Data Regions and Storage

Google Workspace administrators can choose to store data in a specific geographic region (currently the United States or Europe) by using a data region policy. The policy can be applied to a specific organizational unit (OU) in a tenant or at the parent OU. For the interests of Federal agencies, the best practice is to restrict stored data for all users to the U.S. This means applying this setting at the parent OU. Data region storage covers the primary data-at-rest (including backups) for Google Workspace core services (see resources section for services in scope).

At the time of writing, data region policies cannot be applied to data types not specifically listed in documentation linked in the resources section. Notably, this includes logs and cached content.

### Policy

#### GWS.COMMONCONTROLS.15.1v0.1
The data storage region SHALL be set to be the United States for all users in the agency's GWS environment.

- _Rationale_: If not properly regulated, data could be stored in various regions, potentially exposing it to unauthorized entities. By implementing this policy, data is mandated to be stored in the U.S. by making it harder for potential adversaries to compromise the data and conforming to specific regulations related to data governance, security controls, privacy, and data residency.
- _Last modified:_ October 30, 2023

- MITRE ATT&CK TTP Mapping
  - [T1591: Gather Victim Organization Information](https://attack.mitre.org/techniques/T1591/)
    - [T1591:001 Gather Victim Organization Information: Determine Physical Location](https://attack.mitre.org/techniques/T1591/001/)
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.COMMONCONTROLS.15.2v0.1
The supplemental data storage region SHALL NOT be set to 'Russian Federation'.

- _Rationale:_ This policy is aligned with the concept of data sovereignty. Ensuring organizational data is not stored in this specific region affords the administrator of the GWS environment a degree of control and governance over their cloud data. This policy takes into account geopolitical and USG national security concerns.
- _Last modified:_ November 30, 2023

- MITRE ATT&CK TTP Mapping
  - [T1591: Gather Victim Organization Information](https://attack.mitre.org/techniques/T1591/)
    - [T1591:001 Gather Victim Organization Information: Determine Physical Location](https://attack.mitre.org/techniques/T1591/001/)
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

### Resources
-	[GWS Admin Help \| Data regions: Choose a geographic location for your data](https://support.google.com/a/answer/7630496)
-	[GWS Admin Help \| What data is covered by a data region policy?](https://support.google.com/a/answer/9223653)

### Prerequisites

- Super Admin role

### Implementation

#### GWS.COMMONCONTROLS.15.1v0.1 Instructions
To configure Data Regions per the policy:
1.	Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.	Navigate to **Account** -> **Account settings**.
3.	Click the **Data Regions** card.
4.	Click the **Data Regions** policy card.
5.	Select the radio button option: "**United States**"
6.	Click **Save**.

#### GWS.COMMONCONTROLS.15.2v0.1 Instructions
To configure Supplemental Data Storage per the policy:
1.	Sign in to the [Google Admin console](https://admin.google.com) as an administrator.
2.	Navigate to **Account** -> **Account settings**.
3.	Click the **Supplemental Data Storage** card.
4.	Ensure the checkbox for "**Russian Federation**" is unchecked.
6.	Click **Save**.