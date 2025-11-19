package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi01 := {
    "policies": {
        "topOU": {
            "gmail_mail_delegation": {"enableMailDelegation": false},
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_mail_delegation": {"enableMailDelegation": true},
            "gmail_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi01 := {
    "policies": {
        "topOU": {
            "gmail_mail_delegation": {"enableMailDelegation": true},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi01a := {
    "policies": {
        "topOU": {
            "gmail_mail_delegation": {"enableMailDelegation": false},
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_mail_delegation": {"enableMailDelegation": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MailDelegation_Correct_1 if {
    PolicyId := GmailId1_1
    Output := tests with input as GoodGmailApi01

    PassTestResult(PolicyId, Output)
}

test_MailDelegation_Incorrect_1 if {
    PolicyId := GmailId1_1
    Output := tests with input as BadGmailApi01

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_MailDelegation_Incorrect_2 if {
    PolicyId := GmailId1_1
    Output := tests with input as BadGmailApi01a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
