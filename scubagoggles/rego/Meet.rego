package meet

import future.keywords
import data.utils
import data.utils.GetFriendlyEnabledValue
import data.utils.PolicyApiInUse

MeetEnabled(orgunit) := utils.AppEnabled(input.policies, "meet", orgunit)

LogEvents := utils.GetEvents("meet_logs")

##############
# GWS.MEET.1 #
##############

#
# Baseline GWS.MEET.1.1
#--

MeetId1_1 := utils.PolicyIdWithSuffix("GWS.MEET.1.1")

LogMessage1_1 := "SafetyDomainLockProto users_allowed_to_join"

Check1_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_1, utils.TopLevelOU)
    count(events) > 0
}

Check1_1_OK if {PolicyApiInUse}

NonComplianceMessage1_1(value) := sprintf("Who can join meetings is set to: %s",
                                          [value])

GetFriendlyValue1_1(Value) := "all users (including users not signed in with a Google account)" if {
    Value == "ALL"
} else := "users in the same organization" if {
    Value == "SAME_ORGANIZATION_ONLY"
} else := "logged in users" if {
    Value == "LOGGED_IN"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(meetAccess))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    meetAccess := settings.meet_safety_domain.usersAllowedToJoin
    not meetAccess in ["SAME_ORGANIZATION_ONLY", "LOGGED_IN"]
}

tests contains {
    "PolicyId": MeetId1_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_1_OK
}

tests contains {
    "PolicyId": MeetId1_1,
    "Criticality": "Should",
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

##############
# GWS.MEET.2 #
##############

#
# Baseline GWS.MEET.2.1
#--

MeetId2_1 := utils.PolicyIdWithSuffix("GWS.MEET.2.1")

LogMessage2_1 := "SafetyAccessLockProto meetings_allowed_to_join"

Check2_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_1, utils.TopLevelOU)
    count(events) > 0
}

Check2_1_OK if {PolicyApiInUse}

NonComplianceMessage2_1(value) := sprintf("What meetings can users join is set to: %s",
                                          [value])

GetFriendlyValue2_1(Value) := "any meetings (including meetings created with personal accounts)" if {
    Value == "ALL"
} else := "meetings hosted by the same organization" if {
    Value == "SAME_ORGANIZATION_ONLY"
} else := "meetings hosted by any workspace organization" if {
    Value == "ANY_WORKSPACE_ORGANIZATION"
} else := Value

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage2_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(meetAccess))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    meetAccess := settings.meet_safety_access.meetingsAllowedToJoin
    not meetAccess in ["SAME_ORGANIZATION_ONLY", "ANY_WORKSPACE_ORGANIZATION"]
}

tests contains {
    "PolicyId": MeetId2_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check2_1_OK
}

tests contains {
    "PolicyId": MeetId2_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1,
                    "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_1_OK
    Conditions := {count(NonCompliantOUs2_1) == 0,
                   count(NonCompliantGroups2_1) == 0}
    Status := (false in Conditions) == false
}
#--

##############
# GWS.MEET.3 #
##############

#
# Baseline GWS.MEET.3.1
#--

MeetId3_1 := utils.PolicyIdWithSuffix("GWS.MEET.3.1")

LogMessage3_1 := "SafetyModerationLockProto host_management_enabled"

Check3_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage3_1, utils.TopLevelOU)
    count(events) > 0
}

Check3_1_OK if {PolicyApiInUse}

NonComplianceMessage3_1(value) := sprintf("Host management when video calls start is: %s",
                                          [value])

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage3_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups3_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage3_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage3_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyEnabledValue(hostMgt))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    hostMgt := settings.meet_safety_host_management.enableHostManagement
    hostMgt != true
}

tests contains {
        "PolicyId": MeetId3_1,
        "Criticality": "Shall",
        "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check3_1_OK
}

tests contains {
    "PolicyId": MeetId3_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1,
                                         NonCompliantGroups3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1,
                    "NonCompliantGroups": NonCompliantGroups3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check3_1_OK
    Conditions := {count(NonCompliantOUs3_1) == 0, count(NonCompliantGroups3_1) == 0}
    Status := (false in Conditions) == false
}
#--

##############
# GWS.MEET.4 #
##############

#
# Baseline GWS.MEET.4.1
#--

MeetId4_1 := utils.PolicyIdWithSuffix("GWS.MEET.4.1")

LogMessage4_1 := concat("", ["Warn for external participants External or ",
                             "unidentified participants in a meeting are ",
                             "given a label"])

Check4_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage4_1, utils.TopLevelOU)
    count(events) > 0
}

Check4_1_OK if {PolicyApiInUse}

NonComplianceMessage4_1(value) := sprintf("Warning label for external or unidentified meeting participants is: %s",
                                          [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage4_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups4_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage4_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage4_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyEnabledValue(extWarn))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    extWarn := settings.meet_safety_external_participants.enableExternalLabel
    extWarn != true
}

tests contains {
    "PolicyId": MeetId4_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check4_1_OK
}

tests contains {
    "PolicyId": MeetId4_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, NonCompliantGroups4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1, "NonCompliantGroups": NonCompliantGroups4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check4_1_OK
    Conditions := {count(NonCompliantOUs4_1) == 0, count(NonCompliantGroups4_1) == 0}
    Status := (false in Conditions) == false
}
#--

##############
# GWS.MEET.5 #
##############

#
# Baseline GWS.MEET.5.1
#--

MeetId5_1 := utils.PolicyIdWithSuffix("GWS.MEET.5.1")

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": "Users can receive calls from anyone"
}
if {
    some OU in utils.OUsWithEvents
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
}

NonCompliantGroups5_1 contains {
    "Name": Group,
    "Value": "Users can receive calls from anyone"
}
if {
    some Group in utils.GroupsWithEvents
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsGroup(LogEvents, SettingName, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
}

tests contains {
    "PolicyId": MeetId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": MeetId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, NonCompliantGroups5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1, "NonCompliantGroups": NonCompliantGroups5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs5_1) == 0, count(NonCompliantGroups5_1) == 0}
    Status := (false in Conditions) == false
}
