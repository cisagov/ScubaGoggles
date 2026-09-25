package calendar

import future.keywords
import data.utils.FailTestNonCompliant
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCalendarApi03 := {
    "policies": {
        "topOU": {
            "calendar_interoperability": {"enableInteroperability": false},
            "calendar_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "calendar_interoperability": {"enableInteroperability": true},
            "calendar_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCalendarApi03 := {
    "policies": {
        "topOU": {
            "calendar_interoperability": {"enableInteroperability": true},
            "calendar_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_CalendarAPI_Interoperability_Correct_1 if {
    PolicyId := CalendarId3_1
    Output := tests with input as GoodCalendarApi03

    PassTestResult(PolicyId, Output)
}

test_CalendarAPI_Interoperability_Incorrect_1 if {
    PolicyId := CalendarId3_1
    Output := tests with input as BadCalendarApi03

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.CALENDAR.3.2
#--

test_OAuth_Correct_V1 if {
    # Not-Implemented
    PolicyId := CalendarId3_2
    Output := tests with input as {
        "calendar_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    Message := "Currently not able to be tested automatically; please manually check."
    FailTestNonCompliant(PolicyId, Output, Message)
}
#--
