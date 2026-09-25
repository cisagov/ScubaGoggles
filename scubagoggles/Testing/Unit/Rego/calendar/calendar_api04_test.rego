package calendar

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCalendarApi04 := {
    "policies": {
        "topOU": {
            "calendar_appointment_schedules": {"enablePayments": false},
            "calendar_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "calendar_appointment_schedules": {"enablePayments": true},
            "calendar_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCalendarApi04 := {
    "policies": {
        "topOU": {
            "calendar_appointment_schedules": {"enablePayments": true},
            "calendar_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_CalendarAPI_Payments_Correct_1 if {
    PolicyId := CalendarId4_1
    Output := tests with input as GoodCalendarApi04

    PassTestResult(PolicyId, Output)
}

test_CalendarAPI_Payments_Incorrect_1 if {
    PolicyId := CalendarId4_1
    Output := tests with input as BadCalendarApi04

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage4_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
