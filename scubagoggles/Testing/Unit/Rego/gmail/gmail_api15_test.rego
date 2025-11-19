package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi15 := {
    "policies": {
        "topOU": {
            "gmail_enhanced_pre_delivery_message_scanning": {
                "enableImprovedSuspiciousContentDetection": true},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi15 := {
    "policies": {
        "topOU": {
            "gmail_enhanced_pre_delivery_message_scanning": {
                "enableImprovedSuspiciousContentDetection": false},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi15a := {
    "policies": {
        "topOU": {
            "gmail_enhanced_pre_delivery_message_scanning": {
                "enableImprovedSuspiciousContentDetection": true},
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_enhanced_pre_delivery_message_scanning": {
                "enableImprovedSuspiciousContentDetection": false},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_PreScanning_Correct_1 if {
    PolicyId := GmailId15_1
    Output := tests with input as GoodGmailApi15

    PassTestResult(PolicyId, Output)
}

test_PreScanning_Incorrect_1 if {
    PolicyId := GmailId15_1
    Output := tests with input as BadGmailApi15

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage15_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_PreScanning_Incorrect_2 if {
    PolicyId := GmailId15_1
    Output := tests with input as BadGmailApi15a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage15_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
