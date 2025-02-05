package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi10 := {
    "policies": {
        "topOU": {
            "gmail_workspace_sync_for_outlook": {
                "enableGoogleWorkspaceSyncForMicrosoftOutlook": false},
            "gmail_service_status": {"serviceState": "ENABLED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi10 := {
    "policies": {
        "topOU": {
            "gmail_workspace_sync_for_outlook": {
                "enableGoogleWorkspaceSyncForMicrosoftOutlook": true},
            "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_SyncEnable_Correct_1 if {
    PolicyId := GmailId10_1
    Output := tests with input as GoodGmailApi10

    PassTestResult(PolicyId, Output)
}

test_SyncEnable_Incorrect_1 if {
    PolicyId := GmailId10_1
    Output := tests with input as BadGmailApi10

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage10_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
