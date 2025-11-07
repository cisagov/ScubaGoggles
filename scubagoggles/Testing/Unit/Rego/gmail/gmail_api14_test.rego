package gmail

import future.keywords
import data.utils.FailTestNonCompliant
import data.utils.GetFriendlyEnabledValue
import data.utils.PassTestResultWithMessage

GoodGmailApi14 := {
    "policies": {
        "topOU": {
            "gmail_email_spam_filter_ip_allowlist": {"allowedIpAddresses": []},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi14 := {
    "policies": {
        "topOU": {
            "gmail_email_spam_filter_ip_allowlist": {
                "allowedIpAddresses": ["8.8.8.8/24"]},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_Allowlist_Correct_1 if {
    PolicyId := GmailId14_1
    Output := tests with input as GoodGmailApi14

    Message := NonComplianceMessage14_1(GetFriendlyEnabledValue(false), "topOU")
    PassTestResultWithMessage(PolicyId, Output, Message)
}

test_Allowlist_Incorrect_1 if {
    PolicyId := GmailId14_1
    Output := tests with input as BadGmailApi14

    FailTestNonCompliant(PolicyId,
                         Output,
                         NonComplianceMessage14_1(GetFriendlyEnabledValue(true),
                                                  "topOU"))
}
