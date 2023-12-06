package rules
import future.keywords

FilterAlertsEvents(RuleName) := FilteredEvents if
{
    Events := AlertsChangeEvents
    FilteredEvents := {Event | some Event in Events; Event.RuleName == RuleName}
}

FilterReceiversEvents(RuleName) := FilteredEvents if
{
    Events := ReceiversChangeEvents
    FilteredEvents := {Event | some Event in Events; Event.RuleName == RuleName}
}

AlertsChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "RuleName": RuleName,
    "Change": Change
}
if {
    some Item in input.rules_logs.items # For each item...
    some Event in Item.events # For each event in the item...

    # Does this event have the parameters we're looking for?
    "SYSTEM_DEFINED_RULE_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values
    RuleName := [
        Parameter.value | some Parameter in Event.parameters;
        Parameter.name == "SYSTEM_DEFINED_RULE_NAME"][0]
    Change := [
        Parameter.value | some Parameter in Event.parameters;
        Parameter.name == "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE"][0]
    Change != "Status unchanged."
}

ReceiversChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "RuleName": RuleName,
    "Change": Change
}
if {
    some Item in input.rules_logs.items # For each item...
    some Event in Item.events # For each event in the item...

    # Does this event have the parameters we're looking for?
    "SYSTEM_DEFINED_RULE_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values
    RuleName := [
        Parameter.value | some Parameter in Event.parameters;
        Parameter.name == "SYSTEM_DEFINED_RULE_NAME"][0]
    Change := [
        Parameter.value | some Parameter in Event.parameters;
        Parameter.name == "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE"][0]
    Change != "Email notification status unchanged, receivers unchanged."
}

GetLastEvent(Events) := Event if {
    MaxTs := max({Event.Timestamp | some Event in Events})
    some Event in Events
    Event.Timestamp == MaxTs
}

#########################
# GWS.COMMONCONTROLS.15 #
#########################

AlertCenterRules := {
    {
        "RuleName": "Government-backed attacks",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "Warnings about potential government-backed attacks."
    },
    {
        "RuleName": "User-reported phishing",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "A sender has sent messages to your domain that users have classified as phishings."
    },
    {
        "RuleName": "User's Admin privilege revoked",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "A user is revoked of their admin privilege."
    },
    {
        "RuleName": "User suspended for spamming through relay",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Google detected suspicious activity such as spamming through a SMTP ",
            "relay service and suspended the account."
        ])
    },
    {
        "RuleName": "User suspended for spamming",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Google detected suspicious activity such as spamming and suspended the account."
    },
    {
        "RuleName": "User suspended due to suspicious activity",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Google suspended a user's account due to a potential compromise detected."
    },
    {
        "RuleName": "User suspended (Google identity alert)",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "Google detected suspicious activity and suspended the account."
    },
    {
        "RuleName": "User suspended (by admin)",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "An admin has suspended the account."
    },
    {
        "RuleName": "User granted Admin privilege",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "A user is granted an admin privilege."
    },
    {
        "RuleName": "User deleted",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "A user has been deleted from the domain."
    },
    {
        "RuleName": "Suspicious programmatic login",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Google detected suspicious login attempts from potential applications or computer programs."
    },
    {
        "RuleName": "Suspicious message reported",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "A sender has sent messages to your domain that users have classified as spam."
    },
    {
        "RuleName": "Suspicious login",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Google detected a sign-in attempt that doesn't match a user's ",
            "normal behavior, such as a sign-in from an unusual location."
        ])
    },
    {
        "RuleName": "Suspicious device activity",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Provides details if device properties such as device ID, serial number, ",
            "type of device, or device manufacturer are updated."
        ])
    },
    {
        "RuleName": "Suspended user made active",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "A suspended user is made active."
    },
    {
        "RuleName": "Spike in user-reported spam",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "An unusually high volume of messages from a sender that users have marked as spam."
    },
    {
        "RuleName": "Phishing message detected post-delivery",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Messages detected as phishing post-delivery that are automatically reclassified."
    },
    {
        "RuleName": "Phishing in inboxes due to bad whitelist",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Messages classified as spam by Gmail filters delivered to user inboxes due to whitelisting ",
            "settings in the Google Admin console that override the spam filters."
        ])
    },
    {
        "RuleName": "New user added",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "A new user has been added to the domain."
    },
    {
        "RuleName": "Mobile settings changed",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "An admin has changed mobile management settings."
    },
    {
        "RuleName": "Malware message detected post-delivery",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Messages detected as malware post-delivery that are automatically reclassified."
    },
    {
        "RuleName": "Leaked password",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Google detected compromised credentials requiring a reset of the user's password."
    },
    {
        "RuleName": "Google Voice configuration problem",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Auto attendants and ring groups with invalid references may hang up at unexpected times."
    },
    {
        "RuleName": "Google Operations",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Provides details about security and privacy issues that affect your Google Workspace services."
    },
    {
        "RuleName": "Gmail potential employee spoofing",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Incoming messages where a sender's name is in your Google Workspace directory, ",
            "but the mail is not from your company's domains or domain aliases."
        ])
    },
    {
        "RuleName": "Email settings changed",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "An admin has changed Google Workspace Gmail settings."
    },
    {
        "RuleName": "Drive settings changed",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "An admin has changed Google Workspace Drive settings."
    },
    {
        "RuleName": "Domain data export initiated",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "A Super Administrator for your Google account has started exporting data from your domain."
    },
    {
        "RuleName": "Directory sync cancelled due to safeguard threshold exceeded",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Directory sync has been automatically cancelled and disabled as the ",
            "directory sync service detected a possibility to exceed deprovisioning safeguard threshold."
        ])
    },
    {
        "RuleName": "Device compromised",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": "Provides details about devices in your domain that have entered a compromised state."
    },
    {
        "RuleName": "Calendar settings changed",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "An admin has changed Google Workspace Calendar settings."
    },
    {
        "RuleName": "Apps outage alert",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "Alerts about new, updated, or resolved outage on the Google Workspace Status Dashboard."
    },
    {
        "RuleName": "App Maker Cloud SQL setup",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "A user has requested a Google Cloud SQL instance to be set up for use with App Maker."
    },
    {
        "RuleName": "Account suspension warning",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "Google Workspace accounts engaging in suspicious activity may ",
            "have their account suspended. Google Workspace accounts must ",
            "comply with the Google Workspace Terms of Service, Google ",
            "Workspace for Education Terms of Service, Google Cloud Platform ",
            "Terms of Service or Cloud Identity Terms of Service."
        ])
    },
    {
        "RuleName": "[Beta] Client-side encryption service unavailable",
        "DefaultOn": true,
        "Criticality": "Shall",
        "Details": concat("", [
            "A problem has been detected with your client-side encryption service ",
            "indicating an outage or misconfigured setting."
        ])
    },
}

EmailOnlyRules := {
    {
        "RuleName": "TLS failure",
        "DefaultOn": false,
        "Criticality": "Shall",
        "Details": "Messages requiring Transport Layer Security (TLS) can't be delivered."
    },
    {
        "RuleName": "Rate limited recipient",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "A high rate of incoming email indicating a potential malicious attack or misconfigured setting."
    },
    {
        "RuleName": "Smarthost failure",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": "Alerts if a large number of messages can't be delivered to one of your smart host servers."
    },
    {
        "RuleName": "Exchange journaling failure",
        "DefaultOn": false,
        "Criticality": "Should",
        "Details": concat("", [
            "Failures with Exchange journaling that ensures email traffic generated ",
            "by Microsoft® Exchange server users is properly archived in Google Vault."
        ])
    },
}

#
# This pair of tests handles all of the above rules with alert center actions
#--
tests contains {
    "Requirement": Rule.RuleName,
    "PolicyId": "GWS.COMMONCONTROLS.15.1v0.1",
    "Criticality": Rule.Criticality,
    "ReportDetails": Rule.Details,
    "ActualValue": Events,
    "RequirementMet": Rule.DefaultOn,
    "NoSuchEvent": true
}
if {
    some Rule in AlertCenterRules
    Events := FilterAlertsEvents(Rule.RuleName)
    count(Events) == 0
 }

tests contains {
    "Requirement": Rule.RuleName,
    "PolicyId": "GWS.COMMONCONTROLS.15.1v0.1",
    "Criticality": Rule.Criticality,
    "ReportDetails": Rule.Details,
    "ActualValue": Events,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    some Rule in AlertCenterRules
    Events := FilterAlertsEvents(Rule.RuleName)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    Status := LastEvent.Change == "Status changed from OFF to ON."
}
#--

#
# This pair handles the email-only rules
#--
tests contains {
    "Requirement": Rule.RuleName,
    "PolicyId": "GWS.COMMONCONTROLS.15.1v0.1",
    "Criticality": Rule.Criticality,
    "ReportDetails": Rule.Details,
    "ActualValue": Events,
    "RequirementMet": Rule.DefaultOn,
    "NoSuchEvent": true
}
if {
    some Rule in EmailOnlyRules
    Events := FilterReceiversEvents(Rule.RuleName)
    count(Events) == 0
 }

tests contains {
    "Requirement": Rule.RuleName,
    "PolicyId": "GWS.COMMONCONTROLS.15.1v0.1",
    "Criticality": Rule.Criticality,
    "ReportDetails": Rule.Details,
    "ActualValue": Events,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    some Rule in EmailOnlyRules
    Events := FilterReceiversEvents(Rule.RuleName)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    Status := true in {
        contains(LastEvent.Change, "Email notification status changed from OFF to ON"),
        contains(LastEvent.Change, "receivers changed from NULL to")
    }
}
#--