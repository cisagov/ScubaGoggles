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
NonCompliantOUs1_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "SafetyDomainLockProto users_allowed_to_join", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "SafetyDomainLockProto users_allowed_to_join", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "SafetyDomainLockProto users_allowed_to_join", utils.TopLevelOU)
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
NonCompliantOUs2_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "SafetyAccessLockProto meetings_allowed_to_join", OU)
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
    Events := utils.FilterEvents(LogEvents, "SafetyAccessLockProto meetings_allowed_to_join", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "SafetyAccessLockProto meetings_allowed_to_join", utils.TopLevelOU)
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
NonCompliantOUs3_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "SafetyModerationLockProto host_management_enabled", OU)
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
    Events := utils.FilterEvents(LogEvents, "SafetyModerationLockProto host_management_enabled", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "SafetyModerationLockProto host_management_enabled", utils.TopLevelOU)
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
NonCompliantOUs4_1 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
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
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--