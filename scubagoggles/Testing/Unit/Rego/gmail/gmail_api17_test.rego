package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi17 := {
    "policies": {
        "topOU": {
            "gmail_comprehensive_mail_storage": {
                "enabled": true
            },
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi17 := {
    "policies": {
        "topOU": {
            "gmail_comprehensive_mail_storage": {
                "enabled": false
            },
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi17a := {
    "policies": {
        "topOU": {
            "gmail_comprehensive_mail_storage": {
                "enabled": true
            },
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_comprehensive_mail_storage": {
                "enabled": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MailStorage_Correct_1 if {
    PolicyId := GmailId17_1
    Output := tests with input as GoodGmailApi17

    PassTestResult(PolicyId, Output)
}

test_MailStorage_Incorrect_1 if {
    PolicyId := GmailId17_1
    Output := tests with input as BadGmailApi17

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage17_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_MailStorage_Incorrect_2 if {
    PolicyId := GmailId17_1
    Output := tests with input as BadGmailApi17a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage17_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
