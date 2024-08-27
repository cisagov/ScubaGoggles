package groups

import data.utils
import future.keywords

LogEvents := utils.GetEvents("groups_logs")

################
# GWS.GROUPS.1 #
################

#
# Baseline GWS.GROUPS.1.1v0.3
#--

GetFriendlyValue1_1(Value) :=
"disabled" if {
    Value == "CLOSED"
} else := "enabled" if {
    Value == "OPEN"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat("", ["Group access from outside the organization is ",
        GetFriendlyValue1_1(LastEvent.NewValue)])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto collaboration_policy", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "CLOSED"
}

tests contains {
    "PolicyId": "GWS.GROUPS.1.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto collaboration_policy", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.1.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto collaboration_policy", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--


################
# GWS.GROUPS.2 #
################

#
# Baseline GWS.GROUPS.2.1v0.3
#--

GetFriendlyValue2_1(Value) :=
"Group owners have the ability to add external members to the group" if {
    Value != "false"
} else := concat("", ["Group owners do not have the ability to ",
    "add external members to the group"]) if {
    Value == "false"
} else := Value

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue2_1(LastEvent.NewValue)
} if {
    some OU in utils.OUsWithEvents
    SettingName := "GroupsSharingSettingsProto owners_can_allow_external_members"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "GroupsSharingSettingsProto owners_can_allow_external_members"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs":NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto owners_can_allow_external_members"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.GROUPS.3 #
################

#
# Baseline GWS.GROUPS.3.1v0.3
#--

GetFriendlyValue3_1(Value) := concat("", ["Group owners have the ability to allow an ",
    "external non-group member to post to the group"]) if {
    Value == "true"
} else := concat("", ["Group owners do not have the ability to allow an ",
    "external non-group member to post to the group"]) if {
    Value == "false"
} else := Value

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue3_1(LastEvent.NewValue)
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
        "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--


################
# GWS.GROUPS.4 #
################

#
# Baseline GWS.GROUPS.4.1v0.3
#--

GetFriendlyValue4_1(Value) :=
"Anyone in the organization can create groups" if {
    Value == "USERS_IN_DOMAIN"
} else := "Anyone on the internet can create groups" if {
    Value == "WORLD"
} else := Value

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue4_1(LastEvent.NewValue)
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto who_can_create_groups", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ADMIN_ONLY"
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.3",
    "Criticality": "Should",
    "ReportDetails":utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto who_can_create_groups", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto who_can_create_groups", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--


################
# GWS.GROUPS.5 #
################

#
# Baseline GWS.GROUPS.5.1v0.3
#--

GetFriendlyValue5_1(Value) := "owners"
 if {
    Value == "OWNERS"
} else := "managers" if {
    Value == "MANAGERS"
} else := "domain users" if {
    Value == "DOMAIN_USERS"
} else := "anyone on the internet" if {
    Value == "PUBLIC"
} else := Value

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": concat("", ["Permission to view conversations is set to ", GetFriendlyValue5_1(LastEvent.NewValue)])
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto default_view_topics_access_level", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "MEMBERS"
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "GroupsSharingSettingsProto default_view_topics_access_level"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto default_view_topics_access_level"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--


################
# GWS.GROUPS.6 #
################

#
# Baseline GWS.GROUPS.6.1v0.3
#--
CheckGroups6_1Compliance(Events, OUs) := true if {
    Groups := utils.FilterEventsOU(Events, "GroupsSharingSettingsProto allow_unlisted_groups", utils.TopLevelOU)
    count(Groups) > 0
    count(OUs) == 0
}
else := false

GetFriendlyValue6_1(Value) := "Groups can be hidden from the directory" if {
    Value == "true"
} else := "Groups cannot be hidden from the directory" if {
    Value == "false"
} else := Value

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue6_1(LastEvent.NewValue)
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto allow_unlisted_groups", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue":"No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto allow_unlisted_groups", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.3",
    "Criticality": "Shall",
    "ReportDetails":utils.ReportDetails(NonCompliantOUs6_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "GroupsSharingSettingsProto allow_unlisted_groups", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_1) == 0
}
#--

################
# GWS.GROUPS.7 #
################

#
# Baseline GWS.GROUPS.7.1v0.3
#--
NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.whoCanJoin != "CAN_REQUEST_TO_JOIN"
}

NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.whoCanViewMembership != "ALL_MEMBERS_CAN_VIEW"
}

NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.whoCanViewGroup != "ALL_MEMBERS_CAN_VIEW"
}

NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.whoCanModerateMembers != "OWNERS_AND_MANAGERS"
}

NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.allowExternalMembers != "false"
}

NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.whoCanPostMessage != "ALL_MEMBERS_CAN_POST"
}

NonCompliantGroups7_1 contains Group.name if {
    CheckGroups6_1Compliance(LogEvents, NonCompliantOUs6_1) == false
    some Group in input.group_settings
    Group.whoCanContactOwner != "ANYONE_CAN_CONTACT"
}

# if there are no groups, it has to be safe.
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.3",
    "Prerequisites": ["directory/v1/domains/list", "directory/v1/groups/list", "groups-settings/v1/groups/get"],
    "Criticality": "Should",
    "ReportDetails": utils.NoGroupsDetails(Groups),
    "ActualValue": utils.NoGroupsDetails(Groups),
    "RequirementMet": true,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) == 0
}

# if there are groups
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.3",
    "Prerequisites": ["directory/v1/domains/list", "directory/v1/groups/list", "groups-settings/v1/groups/get"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsGroups(NonCompliantGroups7_1),
    "ActualValue": {"NonCompliantGroups": NonCompliantGroups7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) > 0
    Status := count(NonCompliantGroups7_1) == 0
}
#--