package calendar

import data.utils
import future.keywords

LogEvents := utils.GetEvents("calendar_logs")

##################
# GWS.CALENDAR.1 #
##################

#
# Baseline GWS.CALENDAR.1.1v0.3
#--
GetFriendlyValue1_1(Value) := "Share all information, but outsiders cannot change calendars" if {
    Value == "READ_ONLY_ACCESS"
} else := "Share all information, and outsiders can change calendars" if {
    Value == "READ_WRITE_ACCESS"
} else := "Share all information, and allow managing of calendars" if {
    Value == "MANAGE_ACCESS"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "External sharing options for primary calendars is set to",
        GetFriendlyValue1_1(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", OU)
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
    "Value": concat(" ", [
        "External sharing options for primary calendars is set to",
        GetFriendlyValue1_1(LastEvent.NewValue)
    ])
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "SHARING_OUTSIDE_DOMAIN", Group)
    # Ignore Group without any events
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SHOW_ONLY_FREE_BUSY_INFORMATION"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.CALENDAR.1.2v0.3
#--

GetFriendlyValue1_2(Value) := "Secondary Calendars Share all information, but outsiders cannot change calendars." if {
    Value == "READ_ONLY_ACCESS"
} else := "Share all information, and outsiders can change calendars." if {
    Value == "READ_WRITE_ACCESS"
} else := "Share all information, and allow managing of calendars." if {
    Value == "MANAGE_ACCESS"
} else := "Only free/busy information (hide event details)." if {
    Value == "SHOW_ONLY_FREE_BUSY_INFORMATION"
} else := Value


tests contains {
    "PolicyId": "GWS.CALENDAR.1.2v0.3",
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
    "PolicyId": "GWS.CALENDAR.1.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": concat("",[utils.ReportDetailsBoolean(Status), "<br>Highest Level of Sharing: ",
    GetFriendlyValue1_2(LastEvent.NewValue)]),
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
# Baseline GWS.CALENDAR.2.1v0.3
#--

NonCompliantOUs2_1 contains {
    "Name": OU, 
    "Value": "External Sharing Guest Prompt is disabled."
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantGroups2_1 contains {
    "Name": Group, 
    "Value": "External Sharing Guest Prompt is disabled."
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", Group)
    # Ignore groups without any events
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

tests contains {
    "PolicyId": "GWS.CALENDAR.2.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.2.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EXTERNAL_GUEST_PROMPT", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs2_1) == 0, count(NonCompliantGroups2_1) == 0}
    Status := (false in Conditions) == false
}
#--


##################
# GWS.CALENDAR.3 #
##################

#
# Baseline GWS.CALENDAR.3.1v0.3
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.3.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsNoOU(LogEvents, "ENABLE_EWS_INTEROP")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.3.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsBoolean(Status),
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
# Baseline GWS.CALENDAR.3.2v0.3
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.3.2v0.3",
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

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": "Paid calendar appointments are enabled."
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "CalendarAppointmentSlotAdminSettingsProto payments_enabled", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

#
# Baseline GWS.CALENDAR.4.1v0.3
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.4.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "CalendarAppointmentSlotAdminSettingsProto payments_enabled"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.4.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "CalendarAppointmentSlotAdminSettingsProto payments_enabled"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0

}
#--
