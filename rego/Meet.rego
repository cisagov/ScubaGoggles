package meet

import data.utils
import future.keywords

LogEvents := utils.GetEvents("meet_logs")

##############
# GWS.MEET.1 #
##############

#
# Baseline GWS.MEET.1.1v0.1
#--
GetFriendlyValue1_1(Value) := "all users (including users not signed in with a Google account)" if {
    Value == "ALL"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Who can join meetings is set to",
        GetFriendlyValue1_1(LastEvent.NewValue)
    ])
} 
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SafetyDomainLockProto users_allowed_to_join", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SafetyDomainLockProto users_allowed_to_join", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.1.1v0.1",
    "Criticality": "Should",
    # Empty list in next line for non-compliant groups, as Meet settings can't be changed at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SafetyDomainLockProto users_allowed_to_join", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
    # as long as it is not all, this is disabled.
}
#--


##############
# GWS.MEET.2 #
##############

#
# Baseline GWS.MEET.2.1v0.1
#--
GetFriendlyValue2_1(Value) := "any meetings, including meetings created with personal accounts" if {
    Value == "ALL"
} else := Value

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "What meetings can org users join is set to",
        GetFriendlyValue2_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SafetyAccessLockProto meetings_allowed_to_join", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SafetyAccessLockProto meetings_allowed_to_join", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SafetyAccessLockProto meetings_allowed_to_join", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--


##############
# GWS.MEET.3 #
##############

#
# Baseline GWS.MEET.3.1v0.1
#--
GetFriendlyValue3_1(Value) := "off" if {
    Value == "false"
} else := Value

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Host management when video calls start is set to",
        GetFriendlyValue3_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SafetyModerationLockProto host_management_enabled", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
        "PolicyId": "GWS.MEET.3.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SafetyModerationLockProto host_management_enabled", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SafetyModerationLockProto host_management_enabled", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

##############
# GWS.MEET.4 #
##############

#
# Baseline GWS.MEET.4.1v0.1
#--
GetFriendlyValue4_1(Value) := "no warning label" if {
    Value == "false"
} else := Value

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Warning label for external or unidentified meeting participants is set to",
        GetFriendlyValue4_1(LastEvent.NewValue)
    ])  
} 
if {
    some OU in utils.OUsWithEvents
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--