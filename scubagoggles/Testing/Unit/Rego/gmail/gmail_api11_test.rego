package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.GetFriendlyEnabledValue
import data.utils.PassTestResult

GoodGmailApi11 := {
    "policies": {
        "topOU": {
            "gmail_auto_forwarding": {"enableAutoForwarding": false},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi11 := {
    "policies": {
        "topOU": {
            "gmail_auto_forwarding": {"enableAutoForwarding": true},
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_Autoforward_Correct_1 if {
    PolicyId := GmailId11_1
    Output := tests with input as GoodGmailApi11

    PassTestResult(PolicyId, Output)
}

test_Autoforward_Incorrect_1 if {
    PolicyId := GmailId11_1
    Output := tests with input as BadGmailApi11

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage11_1(GetFriendlyEnabledValue(true))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
