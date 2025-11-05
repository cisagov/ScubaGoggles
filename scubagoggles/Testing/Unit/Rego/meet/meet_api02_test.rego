package meet

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodMeetApi02 := {
    "policies": {
        "topOU": {
            "meet_safety_access": {"meetingsAllowedToJoin": "SAME_ORGANIZATION_ONLY"},
            "meet_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "meet_safety_access": {"meetingsAllowedToJoin": "ANY_WORKSPACE_ORGANIZATION"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadMeetApi02 := {
    "policies": {
        "topOU": {
            "meet_safety_access": {"meetingsAllowedToJoin": "ALL"},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MeetAPI_MeetAccess_Correct_1 if {
    PolicyId := MeetId2_1
    Output := tests with input as GoodMeetApi02

    PassTestResult(PolicyId, Output)
}

test_MeetAPI_MeetAccess_Incorrect_1 if {
    PolicyId := MeetId2_1
    Output := tests with input as BadMeetApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
