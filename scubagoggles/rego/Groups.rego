package groups

import future.keywords
import data.utils
import data.utils.PolicyApiInUse

LogEvents := utils.GetEvents("groups_logs")

GroupsEnabled(orgunit) := utils.AppEnabled(input.policies, "groups_for_business", orgunit)

################
# GWS.GROUPS.1 #
################

#
# Baseline GWS.GROUPS.1.1
#--

GroupsId1_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.1.1")

LogMessage1_1 := "GroupsSharingSettingsProto collaboration_policy"

Check1_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_1, utils.TopLevelOU)
    count(events) > 0
}

Check1_1_OK if {PolicyApiInUse}

GetFriendlyValue1_1(Value) := "Users in your domain only" if {
    Value in {"CLOSED", "DOMAIN_USERS_ONLY"}
} else := "Any user" if {
    Value in {"OPEN", "ANYONE_CAN_ACCESS"}
} else := Value

NonComplianceMessage1_1(value) := sprintf("Group access set to: %s", [value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "CLOSED"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(whoCanShare))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    whoCanShare := settings.groups_for_business_groups_sharing.collaborationCapability
    whoCanShare != "DOMAIN_USERS_ONLY"
}

tests contains {
    "PolicyId": GroupsId1_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check1_1_OK
}

tests contains {
    "PolicyId": GroupsId1_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_1_OK
    Status := count(NonCompliantOUs1_1) == 0
}
#--

################
# GWS.GROUPS.2 #
################

#
# Baseline GWS.GROUPS.2.1
#--

GroupsId2_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.2.1")

LogMessage2_1 := "GroupsSharingSettingsProto owners_can_allow_external_members"

Check2_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_1, utils.TopLevelOU)
    count(events) > 0
}

Check2_1_OK if {PolicyApiInUse}

GetFriendlyValue2_1(Value) := "Yes" if {
    Value in {true, "true"}
} else := "No" if {
    Value in {false, "false"}
} else := Value

NonComplianceMessage2_1(value) := sprintf("Allowing external group members is set to: %s", [value])

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(allowExternal))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    allowExternal := settings.groups_for_business_groups_sharing.ownersCanAllowExternalMembers
    allowExternal != false
}

tests contains {
    "PolicyId": GroupsId2_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check2_1_OK
}

tests contains {
    "PolicyId": GroupsId2_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs":NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_1_OK
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.GROUPS.3 #
################

#
# Baseline GWS.GROUPS.3.1
#--

GroupsId3_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.3.1")

LogMessage3_1 := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"

Check3_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage3_1, utils.TopLevelOU)
    count(events) > 0
}

Check3_1_OK if {PolicyApiInUse}

GetFriendlyValue3_1(Value) := "Yes" if {
    Value in {true, "true"}
} else := "No" if {
    Value in {false, "false"}
} else := Value

NonComplianceMessage3_1(value) := sprintf("Allowing external email is set to: %s", [value])

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyValue3_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage3_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyValue3_1(allowExternal))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    allowExternal := settings.groups_for_business_groups_sharing.ownersCanAllowIncomingMailFromPublic
    allowExternal != false
}

tests contains {
    "PolicyId": GroupsId3_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check3_1_OK
}

tests contains {
    "PolicyId": GroupsId3_1,
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

################
# GWS.GROUPS.4 #
################

#
# Baseline GWS.GROUPS.4.1
#--

GroupsId4_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.4.1")

LogMessage4_1 := "GroupsSharingSettingsProto who_can_create_groups"

Check4_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage4_1, utils.TopLevelOU)
    count(events) > 0
}

Check4_1_OK if {PolicyApiInUse}

GetFriendlyValue4_1(Value) := "Administrators only" if {
    Value == "ADMIN_ONLY"
} else := "Users in your domain only" if {
    Value == "USERS_IN_DOMAIN"
} else := "Any user" if {
    Value == "WORLD"
} else := Value

NonComplianceMessage4_1(value) := sprintf("Groups can be created by: %s", [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage4_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ADMIN_ONLY"
}

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(whoCreates))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    whoCreates := settings.groups_for_business_groups_sharing.createGroupsAccessLevel
    whoCreates != "ADMIN_ONLY"
}

tests contains {
    "PolicyId": GroupsId4_1,
    "Criticality": "Should",
    "ReportDetails":utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check4_1_OK
}

tests contains {
    "PolicyId": GroupsId4_1,
    "Criticality": "Should",
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

################
# GWS.GROUPS.5 #
################

#
# Baseline GWS.GROUPS.5.1
#--

GroupsId5_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.5.1")

LogMessage5_1 := "GroupsSharingSettingsProto default_view_topics_access_level"

Check5_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_1, utils.TopLevelOU)
    count(events) > 0
}

Check5_1_OK if {PolicyApiInUse}

GetFriendlyValue5_1(Value) := "Owners" if {
    Value == "OWNERS"
} else := "Managers" if {
    Value == "MANAGERS"
} else := "Group members only" if {
    Value == "GROUP_MEMBERS"
} else := "Users in your domain only" if {
    Value == "DOMAIN_USERS"
} else := "Any user" if {
    Value == "PUBLIC"
} else := Value

NonComplianceMessage5_1(value) := sprintf("Group conversations can be viewed by: %s", [value])

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1(GetFriendlyValue5_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage5_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "MEMBERS"
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1(GetFriendlyValue5_1(whoCanView))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    whoCanView := settings.groups_for_business_groups_sharing.viewTopicsDefaultAccessLevel
    whoCanView != "GROUP_MEMBERS"
}

tests contains {
    "PolicyId": GroupsId5_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check5_1_OK
}

tests contains {
    "PolicyId": GroupsId5_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_1_OK
    Status := count(NonCompliantOUs5_1) == 0
}
#--

################
# GWS.GROUPS.6 #
################

#
# Baseline GWS.GROUPS.6.1
#--

GroupsId6_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.6.1")

LogMessage6_1 := "GroupsSharingSettingsProto allow_unlisted_groups"

Check6_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage6_1, utils.TopLevelOU)
    count(events) > 0
}

Check6_1_OK if {PolicyApiInUse}

GetFriendlyValue6_1(Value) := "Yes" if {
    Value in {true, "true"}
} else := "No" if {
    Value in {false, "false"}
} else := Value

NonComplianceMessage6_1(value) := sprintf("Group may be hidden: %s", [value])

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(canHideGroups))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    canHideGroups := settings.groups_for_business_groups_sharing.ownersCanHideGroups
    canHideGroups != false
}

tests contains {
    "PolicyId": GroupsId6_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue":"No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check6_1_OK
}

tests contains {
    "PolicyId": GroupsId6_1,
    "Criticality": "Shall",
    "ReportDetails":utils.ReportDetails(NonCompliantOUs6_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check6_1_OK
    Status := count(NonCompliantOUs6_1) == 0
}
