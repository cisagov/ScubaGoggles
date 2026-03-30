package commoncontrols

import future.keywords
import data.utils.TestResult

GoodCaseInputApi13 := {
    "policies": {
        "topOU": {
            "rule_system_defined_alerts": [
                {
                    "displayName": "Account suspension warning",
                    "description": "Google Workspace accounts engaging in suspicious activity may have their account suspended. Google Workspace accounts must comply with the Google Workspace Terms of Service, Google Workspace for Education Terms of Service, Google Cloud Platform Terms of Service or Cloud Identity Terms of Service.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Calendar settings changed",
                    "description": "An admin has changed Google Workspace Calendar settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Device compromised",
                    "description": "Provides details about devices in your domain that have entered a compromised state.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Domain data export initiated",
                    "description": "A Super Administrator for your Google account has started exporting data from your domain.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Email settings changed",
                    "description": "An admin has changed Google Workspace Gmail settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Gmail potential employee spoofing",
                    "description": "Incoming messages where a sender's name is in your Google Workspace directory, but the mail is not from your company's domains or domain aliases.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Google Operations",
                    "description": "Provides details about security and privacy issues that affect your Google Workspace services.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Government-backed attacks",
                    "description": "Warnings about potential government-backed attacks.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Leaked password",
                    "description": "Google detected compromised credentials requiring a reset of the user's password.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Malware message detected post-delivery",
                    "description": "Messages detected as malware post-delivery that are automatically reclassified.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Mobile settings changed",
                    "description": "An admin has changed mobile management settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Phishing in inboxes due to bad whitelist",
                    "description": "Messages classified as spam by Gmail filters delivered to user inboxes due to whitelisting settings in the Google Admin console that override the spam filters.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Phishing message detected post-delivery",
                    "description": "Messages detected as phishing post-delivery that are automatically reclassified.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Rate limited recipient",
                    "description": "A high rate of incoming email indicating a potential malicious attack or misconfigured setting.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Spike in user-reported spam",
                    "description": "An unusually high volume of messages from a sender that users have marked as spam.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "SSO profile added",
                    "description": "Alerts you when a new SSO profile allows users to sign in to Google services through your third-party identity provider.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "SSO profile updated",
                    "description": "Alerts you when there's a change to the SSO profile that allows users to sign in to Google services through your third-party identity provider.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Super admin password reset",
                    "description": "Alerts you when the password for a super admin account changes. This admin can manage all features in your Admin console and Admin APIs.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious device activity",
                    "description": "Provides details if device properties such as device ID, serial number, type of device, or device manufacturer are updated.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious login",
                    "description": "Google detected a sign-in attempt that doesn't match a user's normal behavior, such as a sign-in from an unusual location.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious message reported",
                    "description": "A sender has sent messages to your domain that users have classified as spam.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious programmatic login",
                    "description": "Google detected suspicious login attempts from potential applications or computer programs.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User granted Admin privilege",
                    "description": "A user is granted an admin privilege.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended (Google identity alert)",
                    "description": "Google detected suspicious activity and suspended the account.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended due to suspicious activity",
                    "description": "Google suspended a user's account due to a potential compromise detected.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended for spamming through relay",
                    "description": "Google detected suspicious activity such as spamming through a SMTP relay service and suspended the account.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended for spamming",
                    "description": "Google detected suspicious activity such as spamming and suspended the account.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User-reported phishing",
                    "description": "A sender has sent messages to your domain that users have classified as phishings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Drive settings changed",
                    "description": "An admin has changed Google Workspace Drive settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User's Admin privilege revoked",
                    "description": "A user is revoked of their admin privilege.",
                    "state": "ACTIVE"
                }
            ],
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi13 := {
    "policies": {
        "topOU": {
            "rule_system_defined_alerts": [
                {
                    "displayName": "Account suspension warning",
                    "description": "Google Workspace accounts engaging in suspicious activity may have their account suspended. Google Workspace accounts must comply with the Google Workspace Terms of Service, Google Workspace for Education Terms of Service, Google Cloud Platform Terms of Service or Cloud Identity Terms of Service.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Calendar settings changed",
                    "description": "An admin has changed Google Workspace Calendar settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Device compromised",
                    "description": "Provides details about devices in your domain that have entered a compromised state.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Domain data export initiated",
                    "description": "A Super Administrator for your Google account has started exporting data from your domain.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Email settings changed",
                    "description": "An admin has changed Google Workspace Gmail settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Gmail potential employee spoofing",
                    "description": "Incoming messages where a sender's name is in your Google Workspace directory, but the mail is not from your company's domains or domain aliases.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Google Operations",
                    "description": "Provides details about security and privacy issues that affect your Google Workspace services.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Government-backed attacks",
                    "description": "Warnings about potential government-backed attacks.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Leaked password",
                    "description": "Google detected compromised credentials requiring a reset of the user's password.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Malware message detected post-delivery",
                    "description": "Messages detected as malware post-delivery that are automatically reclassified.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Mobile settings changed",
                    "description": "An admin has changed mobile management settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Phishing in inboxes due to bad whitelist",
                    "description": "Messages classified as spam by Gmail filters delivered to user inboxes due to whitelisting settings in the Google Admin console that override the spam filters.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Phishing message detected post-delivery",
                    "description": "Messages detected as phishing post-delivery that are automatically reclassified.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Rate limited recipient",
                    "description": "A high rate of incoming email indicating a potential malicious attack or misconfigured setting.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Spike in user-reported spam",
                    "description": "An unusually high volume of messages from a sender that users have marked as spam.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "SSO profile added",
                    "description": "Alerts you when a new SSO profile allows users to sign in to Google services through your third-party identity provider.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "SSO profile updated",
                    "description": "Alerts you when there's a change to the SSO profile that allows users to sign in to Google services through your third-party identity provider.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Super admin password reset",
                    "description": "Alerts you when the password for a super admin account changes. This admin can manage all features in your Admin console and Admin APIs.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious device activity",
                    "description": "Provides details if device properties such as device ID, serial number, type of device, or device manufacturer are updated.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious login",
                    "description": "Google detected a sign-in attempt that doesn't match a user's normal behavior, such as a sign-in from an unusual location.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious message reported",
                    "description": "A sender has sent messages to your domain that users have classified as spam.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Suspicious programmatic login",
                    "description": "Google detected suspicious login attempts from potential applications or computer programs.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User granted Admin privilege",
                    "description": "A user is granted an admin privilege.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended (Google identity alert)",
                    "description": "Google detected suspicious activity and suspended the account.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended due to suspicious activity",
                    "description": "Google suspended a user's account due to a potential compromise detected.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended for spamming through relay",
                    "description": "Google detected suspicious activity such as spamming through a SMTP relay service and suspended the account.", # regal ignore:line-length
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User suspended for spamming",
                    "description": "Google detected suspicious activity such as spamming and suspended the account.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User-reported phishing",
                    "description": "A sender has sent messages to your domain that users have classified as phishings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "Drive settings changed",
                    "description": "An admin has changed Google Workspace Drive settings.",
                    "state": "ACTIVE"
                },
                {
                    "displayName": "User's Admin privilege revoked",
                    "description": "A user is revoked of their admin privilege.",
                    "state": "ACTIVE"
                }
            ],
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi13a := {
    "policies": {
        "topOU": {
            "rule_system_defined_alerts": [
                {
                    "displayName": "Account suspension warning",
                    "description": "Google Workspace accounts engaging in suspicious activity may have their account suspended. Google Workspace accounts must comply with the Google Workspace Terms of Service, Google Workspace for Education Terms of Service, Google Cloud Platform Terms of Service or Cloud Identity Terms of Service.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Calendar settings changed",
                    "description": "An admin has changed Google Workspace Calendar settings.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Device compromised",
                    "description": "Provides details about devices in your domain that have entered a compromised state.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Domain data export initiated",
                    "description": "A Super Administrator for your Google account has started exporting data from your domain.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Email settings changed",
                    "description": "An admin has changed Google Workspace Gmail settings.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Gmail potential employee spoofing",
                    "description": "Incoming messages where a sender's name is in your Google Workspace directory, but the mail is not from your company's domains or domain aliases.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Google Operations",
                    "description": "Provides details about security and privacy issues that affect your Google Workspace services.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Government-backed attacks",
                    "description": "Warnings about potential government-backed attacks.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Leaked password",
                    "description": "Google detected compromised credentials requiring a reset of the user's password.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Malware message detected post-delivery",
                    "description": "Messages detected as malware post-delivery that are automatically reclassified.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Mobile settings changed",
                    "description": "An admin has changed mobile management settings.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Phishing in inboxes due to bad whitelist",
                    "description": "Messages classified as spam by Gmail filters delivered to user inboxes due to whitelisting settings in the Google Admin console that override the spam filters.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Phishing message detected post-delivery",
                    "description": "Messages detected as phishing post-delivery that are automatically reclassified.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Rate limited recipient",
                    "description": "A high rate of incoming email indicating a potential malicious attack or misconfigured setting.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Spike in user-reported spam",
                    "description": "An unusually high volume of messages from a sender that users have marked as spam.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "SSO profile added",
                    "description": "Alerts you when a new SSO profile allows users to sign in to Google services through your third-party identity provider.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "SSO profile updated",
                    "description": "Alerts you when there's a change to the SSO profile that allows users to sign in to Google services through your third-party identity provider.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Super admin password reset",
                    "description": "Alerts you when the password for a super admin account changes. This admin can manage all features in your Admin console and Admin APIs.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Suspicious device activity",
                    "description": "Provides details if device properties such as device ID, serial number, type of device, or device manufacturer are updated.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Suspicious login",
                    "description": "Google detected a sign-in attempt that doesn't match a user's normal behavior, such as a sign-in from an unusual location.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Suspicious message reported",
                    "description": "A sender has sent messages to your domain that users have classified as spam.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Suspicious programmatic login",
                    "description": "Google detected suspicious login attempts from potential applications or computer programs.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User granted Admin privilege",
                    "description": "A user is granted an admin privilege.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User suspended (Google identity alert)",
                    "description": "Google detected suspicious activity and suspended the account.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User suspended due to suspicious activity",
                    "description": "Google suspended a user's account due to a potential compromise detected.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User suspended for spamming through relay",
                    "description": "Google detected suspicious activity such as spamming through a SMTP relay service and suspended the account.", # regal ignore:line-length
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User suspended for spamming",
                    "description": "Google detected suspicious activity such as spamming and suspended the account.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User-reported phishing",
                    "description": "A sender has sent messages to your domain that users have classified as phishings.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "Drive settings changed",
                    "description": "An admin has changed Google Workspace Drive settings.",
                    "state": "INACTIVE"
                },
                {
                    "displayName": "User's Admin privilege revoked",
                    "description": "A user is revoked of their admin privilege.",
                    "state": "INACTIVE"
                }
            ],
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}


test_SystemRules_Correct_1 if {
    PolicyId := CommonControlsId13_1
    Output := tests with input as GoodCaseInputApi13

    TestResult(PolicyId, Output, CommonControls13_1_Details(30, 30), true)
}

test_SystemRules_Incorrect_1 if {
    PolicyId := CommonControlsId13_1
    Output := tests with input as BadCaseInputApi13

    TestResult(PolicyId, Output, CommonControls13_1_Details(30, 27), false)
}

test_SystemRules_Incorrect_2 if {
    PolicyId := CommonControlsId13_1
    Output := tests with input as BadCaseInputApi13a

    TestResult(PolicyId, Output, CommonControls13_1_Details(30, 0), false)
}
