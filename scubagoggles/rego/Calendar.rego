package calendar

import future.keywords
import data.utils
import data.utils.PolicyApiInUse

LogEvents := utils.GetEvents("calendar_logs")

CalendarEnabled(orgunit) := utils.AppEnabled(input.policies, "calendar", orgunit)

##################
# GWS.CALENDAR.1 #
##################

#
# Baseline GWS.CALENDAR.1.1
#--

CalendarId1_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.1.1")

LogMessage1_1 := "SHARING_OUTSIDE_DOMAIN"

Check1_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_1, utils.TopLevelOU)
    count(events) > 0
}

Check1_1_OK if {PolicyApiInUse}

GetFriendlyValue1_1(Value) := "Share all information, but outsiders cannot change calendars" if {
    Value in {"EXTERNAL_ALL_INFO_READ_ONLY", "READ_ONLY_ACCESS"}
} else := "Share all information, and outsiders can change calendars" if {
    Value in {"EXTERNAL_ALL_INFO_READ_WRITE", "READ_WRITE_ACCESS"}
} else := "Share all information, and allow managing of calendars" if {
    Value in {"EXTERNAL_ALL_INFO_READ_WRITE_MANAGE", "MANAGE_ACCESS"}
} else := Value

SharingFmtMsg := "External sharing options for %s calendars is set to: %s"
NonComplianceMessage1_1(value) := sprintf(SharingFmtMsg, ["primary", value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SHOW_ONLY_FREE_BUSY_INFORMATION"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_1, Group)
    # Ignore Group without any events
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SHOW_ONLY_FREE_BUSY_INFORMATION"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check1_1_OK
}

tests contains {
    "PolicyId": CalendarId1_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_1_OK
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.CALENDAR.1.2
#--

CalendarId1_2 := utils.PolicyIdWithSuffix("GWS.CALENDAR.1.2")

LogMessage1_2 := "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"

Check1_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_2, utils.TopLevelOU)
    count(events) > 0
}

Check1_2_OK if {PolicyApiInUse}

GetFriendlyValue1_2(Value) := GetFriendlyValue1_1(Value)

NonComplianceMessage1_2(value) := sprintf(SharingFmtMsg, ["secondary", value])

NonCompliantOUs1_2 contains {
    "Name": utils.TopLevelOU,
    "Value": NonComplianceMessage1_2(GetFriendlyValue1_2(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    Events := utils.FilterEventsNoOU(LogEvents, LogMessage1_2)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SHOW_ONLY_FREE_BUSY_INFORMATION"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_2_OK
}

tests contains {
    "PolicyId": CalendarId1_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_2_OK
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

LogMessage2_1 := "ENABLE_EXTERNAL_GUEST_PROMPT"

Check2_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_1, utils.TopLevelOU)
    count(events) > 0
}

Check2_1_OK if {PolicyApiInUse}

NonComplianceMessage2_1(value) := sprintf("External Sharing Guest Prompt is %s",
                                          [value])

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(utils.GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_1(utils.GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage2_1, Group)
    # Ignore groups without any events
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check2_1_OK
}

tests contains {
    "PolicyId": CalendarId2_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_1_OK
    Conditions := {count(NonCompliantOUs2_1) == 0, count(NonCompliantGroups2_1) == 0}
    Status := (false in Conditions) == false
}
#--

##################
# GWS.CALENDAR.3 #
##################

#
# Baseline GWS.CALENDAR.3.1
#--

CalendarId3_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.3.1")

LogMessage3_1 := "ENABLE_EWS_INTEROP"

Check3_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage3_1, utils.TopLevelOU)
    count(events) > 0
}

Check3_1_OK if {PolicyApiInUse}

NonComplianceMessage3_1(value) := sprintf("Calendar interoperation is %s",
                                          [value])

NonCompliantOUs3_1 contains {
    "Name": utils.TopLevelOU,
    "Value": NonComplianceMessage3_1(utils.GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    Events := utils.FilterEventsNoOU(LogEvents, LogMessage3_1)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

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
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check3_1_OK
}

tests contains {
    "PolicyId": CalendarId3_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check3_1_OK
    Status := count(NonCompliantOUs3_1) == 0
}
#--

#
# Baseline GWS.CALENDAR.3.2
#--

CalendarId3_2 := utils.PolicyIdWithSuffix("GWS.CALENDAR.3.2")

tests contains {
    "PolicyId": CalendarId3_2,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##################
# GWS.CALENDAR.4 #
##################

#
# Baseline GWS.CALENDAR.4.1
#--

CalendarId4_1 := utils.PolicyIdWithSuffix("GWS.CALENDAR.4.1")

LogMessage4_1 := "CalendarAppointmentSlotAdminSettingsProto payments_enabled"

Check4_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage4_1, utils.TopLevelOU)
    count(events) > 0
}

Check4_1_OK if {PolicyApiInUse}

NonComplianceMessage4_1(value) := sprintf("Paid calendar appointments are %s",
                                          [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(utils.GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage4_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check4_1_OK
}

tests contains {
    "PolicyId": CalendarId4_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check4_1_OK
    Status := count(NonCompliantOUs4_1) == 0
}
#--
