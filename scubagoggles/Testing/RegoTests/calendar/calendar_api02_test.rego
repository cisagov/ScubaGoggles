package calendar

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCalendarApi02 := {
    "policies": {
        "topOU": {
            "calendar_external_invitations": {"warnOnInvite": true},
            "calendar_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "calendar_external_invitations": {"warnOnInvite": false},
            "calendar_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCalendarApi02 := {
    "policies": {
        "topOU": {
            "calendar_external_invitations": {"warnOnInvite": false},
            "calendar_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_CalendarAPI_WarnExternal_Correct_1 if {
    PolicyId := CalendarId2_1
    Output := tests with input as GoodCalendarApi02

    PassTestResult(PolicyId, Output)
}

test_CalendarAPI_WarnExternal_Incorrect_1 if {
    PolicyId := CalendarId2_1
    Output := tests with input as BadCalendarApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
