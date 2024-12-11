package meet

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodMeetApi04 := {
    "policies": {
        "topOU": {
            "meet_safety_external_participants": {"enableExternalLabel": true},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadMeetApi04 := {
    "policies": {
        "topOU": {
            "meet_safety_external_participants": {"enableExternalLabel": false},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MeetAPI_ExtWarn_Correct_1 if {
    PolicyId := MeetId4_1
    Output := tests with input as GoodMeetApi04

    PassTestResult(PolicyId, Output)
}

test_MeetAPI_ExtWarn_Incorrect_1 if {
    PolicyId := MeetId4_1
    Output := tests with input as BadMeetApi04

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage4_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
