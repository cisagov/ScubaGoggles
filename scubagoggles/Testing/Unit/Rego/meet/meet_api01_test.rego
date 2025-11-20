package meet

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodMeetApi01 := {
    "policies": {
        "topOU": {
            "meet_safety_access_type": {"access_type": "TRUSTED"},
            "meet_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "meet_safety_access_type": {"access_type": "RESTRICTED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadMeetApi01 := {
    "policies": {
        "topOU": {
            "meet_safety_access_type": {"access_type": "OPEN"},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MeetAPI_UserAccessType_Correct_1 if {
    PolicyId := MeetId1_1
    Output := tests with input as GoodMeetApi01

    PassTestResult(PolicyId, Output)
}

test_MeetAPI_UserAccessType_Incorrect_1 if {
    PolicyId := MeetId1_1
    Output := tests with input as BadMeetApi01

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("OPEN"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
