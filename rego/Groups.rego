package groups

import data.utils
import future.keywords

NoGroupsDetails(Groups) := "No Groups found in Organization." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := "Requirement met in all Groups." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := Message if {
    count(Groups) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", Groups), "."])
}

################
# GWS.GROUPS.1 #
################

#
# Baseline GWS.GROUPS.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
     some OU in utils.OUsWithEvents
     Events := utils.FilterEvents("GroupsSharingSettingsProto collaboration_policy", OU)
     count(Events) > 0 # Ignore OUs without any events. We're already
     # asserting that the top-level OU has at least one event; for all
     # other OUs we assume they inherit from a parent OU if they have
     # no events.
     LastEvent := utils.GetLastEvent(Events)
     LastEvent.NewValue != "CLOSED"
 }

tests contains {
    "PolicyId": "GWS.GROUPS.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("GroupsSharingSettingsProto collaboration_policy", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("GroupsSharingSettingsProto collaboration_policy", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--


################
# GWS.GROUPS.2 #
################

#
# Baseline GWS.GROUPS.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("GroupsSharingSettingsProto owners_can_allow_external_members", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("GroupsSharingSettingsProto owners_can_allow_external_members", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs":NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("GroupsSharingSettingsProto owners_can_allow_external_members", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.GROUPS.3 #
################

#
# Baseline GWS.GROUPS.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
    Events := utils.FilterEvents(SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
    Events := utils.FilterEvents(SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--


################
# GWS.GROUPS.4 #
################

#
# Baseline GWS.GROUPS.4.1v0.1
#--
NonCompliantOUs4_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("GroupsSharingSettingsProto who_can_create_groups", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ADMIN_ONLY"
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails":utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("GroupsSharingSettingsProto who_can_create_groups", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("GroupsSharingSettingsProto who_can_create_groups", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--


################
# GWS.GROUPS.5 #
################

#
# Baseline GWS.GROUPS.5.1v0.1
#--
NonCompliantOUs5_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("GroupsSharingSettingsProto default_view_topics_access_level", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "MEMBERS"
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("GroupsSharingSettingsProto default_view_topics_access_level", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("GroupsSharingSettingsProto default_view_topics_access_level", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--


################
# GWS.GROUPS.6 #
################

#
# Baseline GWS.GROUPS.6.1v0.1
#--
NonCompliantOUs6_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("GroupsSharingSettingsProto allow_unlisted_groups", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue":"No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("GroupsSharingSettingsProto allow_unlisted_groups", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails":utils.ReportDetailsOUs(NonCompliantOUs6_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("GroupsSharingSettingsProto allow_unlisted_groups", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_1) == 0
}
#--

################
# GWS.GROUPS.7 #
################

#
# Baseline GWS.GROUPS.7.1v0.1
#--
# This sets up for a logical OR between all the settings. If one of them is false,
# it will trigger the function and add the group to the list.
IsGroupRestricted(Group) {
    Group.whoCanJoin != "CAN_REQUEST_TO_JOIN"
}

IsGroupRestricted(Group) {
    Group.whoCanViewMembership != "ALL_MEMBERS_CAN_VIEW"
}

IsGroupRestricted(Group) {
    Group.whoCanViewGroup != "ALL_MEMBERS_CAN_VIEW"
}

IsGroupRestricted(Group) {
    Group.whoCanModerateMembers != "OWNERS_AND_MANAGERS"
}

IsGroupRestricted(Group) {
    Group.allowExternalMembers != "false"
}

IsGroupRestricted(Group) {
    Group.whoCanPostMessage != "ALL_MEMBERS_CAN_POST"
}

IsGroupRestricted(Group) {
    Group.whoCanContactOwner != "ANYONE_CAN_CONTACT"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    IsGroupRestricted(Group)
}

# if there are no groups, it has to be safe.
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoGroupsDetails(Groups),
    "ActualValue": NoGroupsDetails(Groups),
    "RequirementMet": true,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) == 0
}

# if there are groups
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsGroups(NonCompliantGroups7_1),
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