package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi08 := {
    "policies": {
        "topOU": {
            "gmail_user_email_uploads": {"enableMailAndContactsImport": false},
            "gmail_service_status": {"serviceState": "ENABLED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi08 := {
    "policies": {
        "topOU": {
            "gmail_user_email_uploads": {"enableMailAndContactsImport": true},
            "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_EmailUploads_Correct_1 if {
    PolicyId := GmailId8_1
    Output := tests with input as GoodGmailApi08

    PassTestResult(PolicyId, Output)
}

test_EmailUploads_Incorrect_1 if {
    PolicyId := GmailId8_1
    Output := tests with input as BadGmailApi08

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage8_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
