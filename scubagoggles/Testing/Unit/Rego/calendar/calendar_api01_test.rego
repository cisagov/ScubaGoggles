package calendar

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCalendarApi01 := {
    "policies": {
        "topOU": {
            "calendar_primary_calendar_max_allowed_external_sharing": {
                "maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"},
              "calendar_secondary_calendar_max_allowed_external_sharing": {
                "maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"},
            "calendar_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "calendar_primary_calendar_max_allowed_external_sharing": {
                "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE"},
              "calendar_secondary_calendar_max_allowed_external_sharing": {
                "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE"},
            "calendar_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCalendarApi01 := {
    "policies": {
        "topOU": {
            "calendar_primary_calendar_max_allowed_external_sharing": {
                "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE"},
              "calendar_secondary_calendar_max_allowed_external_sharing": {
                "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE"},
            "calendar_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_CalendarAPI_PrimaryShare_Correct_1 if {
    PolicyId := CalendarId1_1
    Output := tests with input as GoodCalendarApi01

    PassTestResult(PolicyId, Output)
}

test_CalendarAPI_PrimaryShare_Incorrect_1 if {
    PolicyId := CalendarId1_1
    Output := tests with input as BadCalendarApi01

    failedMsgValue := GetFriendlyValue1_1("EXTERNAL_ALL_INFO_READ_WRITE")
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1(failedMsgValue)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CalendarAPI_SecondaryShare_Correct_1 if {
    PolicyId := CalendarId1_2
    Output := tests with input as GoodCalendarApi01

    PassTestResult(PolicyId, Output)
}

test_CalendarAPI_SecondaryShare_Incorrect_1 if {
    PolicyId := CalendarId1_2
    Output := tests with input as BadCalendarApi01

    failedMsgValue := GetFriendlyValue1_2("EXTERNAL_ALL_INFO_READ_WRITE_MANAGE")
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_2(failedMsgValue)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
