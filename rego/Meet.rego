package meet
import future.keywords
import data.utils.TopLevelOU
import data.utils.GetLastEvent
import data.utils.FilterEvents
import data.utils.OUsWithEvents
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

##############
# GWS.MEET.1 #
##############

#
# Baseline GWS.MEET.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents("SafetyDomainLockProto users_allowed_to_join", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("SafetyDomainLockProto users_allowed_to_join", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("SafetyDomainLockProto users_allowed_to_join", TopLevelOU)
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
    some OU in OUsWithEvents
    Events := FilterEvents("SafetyAccessLockProto meetings_allowed_to_join", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("SafetyAccessLockProto meetings_allowed_to_join", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("SafetyAccessLockProto meetings_allowed_to_join", TopLevelOU)
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
    some OU in OUsWithEvents
    Events := FilterEvents("SafetyModerationLockProto host_management_enabled", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
        "PolicyId": "GWS.MEET.3.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("SafetyModerationLockProto host_management_enabled", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("SafetyModerationLockProto host_management_enabled", TopLevelOU)
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
    some OU in OUsWithEvents
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := FilterEvents(SettingName, OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.MEET.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := FilterEvents(SettingName, TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.MEET.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Warn for external participants External or unidentified participants in a meeting are given a label"
    Events := FilterEvents(SettingName, TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--