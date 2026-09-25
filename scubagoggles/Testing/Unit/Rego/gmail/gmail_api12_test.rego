package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi12 := {
    "policies": {
        "topOU": {
            "gmail_per_user_outbound_gateway": {
                "allowUsersToUseExternalSmtpServers": false},
            "gmail_service_status": {"serviceState": "ENABLED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi12 := {
    "policies": {
        "topOU": {
            "gmail_per_user_outbound_gateway": {
                "allowUsersToUseExternalSmtpServers": true},
            "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_OutGateways_Correct_1 if {
    PolicyId := GmailId12_1
    Output := tests with input as GoodGmailApi12

    PassTestResult(PolicyId, Output)
}

test_OutGateways_Incorrect_1 if {
    PolicyId := GmailId12_1
    Output := tests with input as BadGmailApi12

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage12_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
