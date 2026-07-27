package meet

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodMeetApi05 := {
    "policies": {
        "topOU": {
            "meet_automatic_recording": {"enabled": false},
            "meet_automatic_transcription": {"enabled": false},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadMeetApi05 := {
    "policies": {
        "topOU": {
            "meet_automatic_recording": {"enabled": true},
            "meet_automatic_transcription": {"enabled": true},
            "meet_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_AutoRecord_Correct_1 if {
    PolicyId := MeetId5_1
    Output := tests with input as GoodMeetApi05

    PassTestResult(PolicyId, Output)
}

test_AutoRecord_Incorrect_1 if {
    PolicyId := MeetId5_1
    Output := tests with input as BadMeetApi05

    failedOU := [{"Name": "topOU",
                 "Value": "Automatic recording is enabled."}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AutoTranscribe_Correct_1 if {
    PolicyId := MeetId5_2
    Output := tests with input as GoodMeetApi05

    PassTestResult(PolicyId, Output)
}

test_AutoTranscribe_Incorrect_1 if {
    PolicyId := MeetId5_2
    Output := tests with input as BadMeetApi05

    failedOU := [{"Name": "topOU",
                 "Value": "Automatic transcription is enabled."}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
