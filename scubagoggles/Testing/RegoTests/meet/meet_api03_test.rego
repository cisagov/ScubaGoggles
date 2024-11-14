package meet

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodMeetApi03 := {
    "policies": {
        "topOU": {
            "meet_safety_host_management": {"enableHostManagement": true},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadMeetApi03 := {
    "policies": {
        "topOU": {
            "meet_safety_host_management": {"enableHostManagement": false},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MeetAPI_HostMgt_Correct_1 if {
    PolicyId := MeetId3_1
    Output := tests with input as GoodMeetApi03

    PassTestResult(PolicyId, Output)
}

test_MeetAPI_HostMgt_Incorrect_1 if {
    PolicyId := MeetId3_1
    Output := tests with input as BadMeetApi03

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
