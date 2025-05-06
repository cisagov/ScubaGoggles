package calendar

import future.keywords
import data.utils

CalendarEnabled(orgunit) := utils.AppEnabled(input.policies, "calendar", orgunit)

##################
# GWS.CALENDAR.1 #
##################

#
# Baseline GWS.CALENDAR.1.1
#--

CalendarId1_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.1.1")

GetFriendlyValue1_1(Value) := "Share all information, but outsiders cannot change calendars" if {
    Value == "EXTERNAL_ALL_INFO_READ_ONLY"
} else := "Share all information, and outsiders can change calendars" if {
    Value == "EXTERNAL_ALL_INFO_READ_WRITE"
} else := "Share all information, and allow managing of calendars" if {
    Value == "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE"
} else := Value

SharingFmtMsg := "External sharing options for %s calendars is set to: %s"
NonComplianceMessage1_1(value) := sprintf(SharingFmtMsg, ["primary", value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(primaryShare))
}
if {
    some OU, settings in input.policies
    CalendarEnabled(OU)
    section := settings.calendar_primary_calendar_max_allowed_external_sharing
    primaryShare := section.maxAllowedExternalSharing
    primaryShare != "EXTERNAL_FREE_BUSY_ONLY"
}

tests contains {
    "PolicyId": CalendarId1_1,
    "Prerequisites": [
        "policy/calendar_service_status.serviceState",
        "policy/calendar_primary_calendar_max_allowed_external_sharing.maxAllowedExternalSharing"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CALENDAR.1.2
#--

CalendarId1_2 := utils.PolicyIdWithSuffix("GWS.CALENDAR.1.2")

GetFriendlyValue1_2(Value) := GetFriendlyValue1_1(Value)

NonComplianceMessage1_2(value) := sprintf(SharingFmtMsg, ["secondary", value])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetFriendlyValue1_2(secondaryShare))
}
if {
    some OU, settings in input.policies
    CalendarEnabled(OU)
    section := settings.calendar_secondary_calendar_max_allowed_external_sharing
    secondaryShare := section.maxAllowedExternalSharing
    secondaryShare != "EXTERNAL_FREE_BUSY_ONLY"
}

tests contains {
    "PolicyId": CalendarId1_2,
    "Prerequisites": [
        "policy/calendar_service_status.serviceState",
        "policy/calendar_secondary_calendar_max_allowed_external_sharing.maxAllowedExternalSharing"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_2) == 0
}
#--

##################
# GWS.CALENDAR.2 #
##################

#
# Baseline GWS.CALENDAR.2.1
#--

CalendarId2_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.2.1")

NonComplianceMessage2_1(value) := sprintf("External Sharing Guest Prompt is %s",
                                          [value])

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(utils.GetFriendlyEnabledValue(extWarnPrompt))
}
if {
    some OU, settings in input.policies
    CalendarEnabled(OU)
    extWarnPrompt := settings.calendar_external_invitations.warnOnInvite
    extWarnPrompt != true
}

tests contains {
    "PolicyId": CalendarId2_1,
    "Prerequisites": [
        "policy/calendar_service_status.serviceState",
        "policy/calendar_external_invitations.warnOnInvite"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_1) == 0
}
#--

##################
# GWS.CALENDAR.3 #
##################

#
# Baseline GWS.CALENDAR.3.1
#--

CalendarId3_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.3.1")

NonComplianceMessage3_1(value) := sprintf("Calendar interoperation is %s",
                                          [value])

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(utils.GetFriendlyEnabledValue(interoperability))
}
if {
    some OU, settings in input.policies
    CalendarEnabled(OU)
    interoperability := settings.calendar_interoperability.enableInteroperability
    interoperability != false
}

tests contains {
    "PolicyId": CalendarId3_1,
    "Prerequisites": [
        "policy/calendar_service_status.serviceState",
        "policy/calendar_interoperability.enableInteroperability"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs3_1) == 0
}
#--

#
# Baseline GWS.CALENDAR.3.2
#--

CalendarId3_2 := utils.PolicyIdWithSuffix("GWS.CALENDAR.3.2")

tests contains {
    "PolicyId": CalendarId3_2,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

##################
# GWS.CALENDAR.4 #
##################

#
# Baseline GWS.CALENDAR.4.1
#--

CalendarId4_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.4.1")

NonComplianceMessage4_1(value) := sprintf("Paid calendar appointments are %s",
                                          [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(utils.GetFriendlyEnabledValue(payments))
}
if {
    some OU, settings in input.policies
    CalendarEnabled(OU)
    payments := settings.calendar_appointment_schedules.enablePayments
    payments != false
}

tests contains {
    "PolicyId": CalendarId4_1,
    "Prerequisites": [
        "policy/calendar_service_status.serviceState",
        "policy/calendar_appointment_schedules.enablePayments"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs4_1) == 0
}
#--
