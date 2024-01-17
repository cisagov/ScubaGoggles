package calendar

import data.utils
import future.keywords

LogEvents := utils.GetEvents("calendar_logs")

##################
# GWS.CALENDAR.1 #
##################

#
# Baseline GWS.CALENDAR.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "SHARING_OUTSIDE_DOMAIN", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SHOW_ONLY_FREE_BUSY_INFORMATION"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CALENDAR.1.2v0.1
#--
ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "SHOW_ONLY_FREE_BUSY_INFORMATION"
    Description := concat("", [
        "<span class=setting>Only free busy/information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName
    ])
}

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "READ_ONLY_ACCESS"
    Description := concat("", [
        "<span class=setting>All information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName,
        " but outsiders cannot change calendars."
    ])
}

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "READ_WRITE_ACCESS"
    Description := concat("", [
        "<span class=setting>All information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName,
        " and outsiders can change calendars."
    ])
}

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "MANAGE_ACCESS"
    Description := concat("", [
        "<span class=setting>All information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName,
        " and outsiders can manage calendars"
    ])
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsNoOU(LogEvents, "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": ExtSharingSecondaryCalSettingDetailsStr(LastEvent),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsNoOU(LogEvents, "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR")
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := LastEvent.NewValue == "SHOW_ONLY_FREE_BUSY_INFORMATION"
}
#--


##################
# GWS.CALENDAR.2 #
##################

#
# Baseline GWS.CALENDAR.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

tests contains {
    "PolicyId": "GWS.CALENDAR.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--


##################
# GWS.CALENDAR.3 #
##################

CalInteropManSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "true"
    Description := concat("", [
        "<span class=setting>Calendar interop is enabled </span> for ",
        LastEvent.DomainName
    ])
}

CalInteropManSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "false"
    Description := concat("", [
        "<span class=setting>Calendar interop is not enabled </span> for ",
        LastEvent.DomainName
    ])
}

#
# Baseline GWS.CALENDAR.3.1v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsNoOU(LogEvents, "ENABLE_EWS_INTEROP")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": CalInteropManSettingDetailsStr(LastEvent),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsNoOU(LogEvents, "ENABLE_EWS_INTEROP")
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := LastEvent.NewValue == "false"
}
#--


#
# Baseline GWS.CALENDAR.3.2v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.3.2v0.1",
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

NonCompliantOUs4_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "CalendarAppointmentSlotAdminSettingsProto payments_enabled", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

#
# Baseline GWS.CALENDAR.4.1v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "CalendarAppointmentSlotAdminSettingsProto payments_enabled"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "CalendarAppointmentSlotAdminSettingsProto payments_enabled"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--