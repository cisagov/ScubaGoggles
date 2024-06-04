package drive

import data.utils
import future.keywords

LogEvents := utils.GetEvents("drive_logs")

###################
# GWS.DRIVEDOCS.1 #
###################

#
# Baseline GWS.DRIVEDOCS.1.1v0.1
#--
GetFriendlyValue1_1(Value) := concat("", ["Files owned by users or shared drives ",
    "can be shared with Google accounts in compatible allowlisted domains"]) if {
    Value == "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING_MAY_RECEIVE_FILES_FROM_ANYONE"
}
else := concat("", ["Files owned by users or shared drives ",
    "can be shared outside of the organization"]) if {
    Value == "SHARING_ALLOWED"
} else := concat("", ["Files owned by users or shared drives ",
    "can be shared outside of the organization with a warning"]) if {
    Value == "SHARING_ALLOWED_WITH_WARNING"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue1_1(LastEvent.NewValue)
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT",
    "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES"}
    not LastEvent.NewValue in AcceptableValues
}


NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": GetFriendlyValue1_1(LastEvent.NewValue)
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "SHARING_OUTSIDE_DOMAIN", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT",
    "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES"}
    not LastEvent.NewValue in AcceptableValues
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.2v0.1
#--


GetFriendlyValue1_2(Value) := "Users cannot recieve files outside the domain" if {
    contains("SHARING_NOT_ALLOWED INHERIT_FROM_PARENT", Value) == true
}
else := "Users can recieve files outside the domain"

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": GetFriendlyValue1_2(LastEvent.NewValue)
    }
    if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues = {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT", 
        "TRUSTED_DOMAINS_ALLOWED", "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING"}
    not LastEvent.NewValue in AcceptableValues
}

NonCompliantGroups1_2 contains {
    "Name": Group,
    "Value": GetFriendlyValue1_2(LastEvent.NewValue)
    }
    if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "SHARING_OUTSIDE_DOMAIN", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues = {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT", 
        "TRUSTED_DOMAINS_ALLOWED", "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING"}
    not LastEvent.NewValue in AcceptableValues
    }

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.2v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.2v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, NonCompliantGroups1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2,
        "NonCompliantGroups": NonCompliantGroups1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_2) == 0, count(NonCompliantGroups1_2) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.3v0.1
#--

GetFriendlyValue1_3(Value, AcceptableValues) := "External Sharing Warning is Enabled" if {
    Value in AcceptableValues == true
}
else := "External Sharing Warning is Disabled"


NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": GetFriendlyValue1_3(LastEvent.NewValue, AcceptableValues)
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"SHARING_ALLOWED_WITH_WARNING", "SHARING_NOT_ALLOWED",
    "INHERIT_FROM_PARENT", "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES",
    "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING", 
    "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING_MAY_RECEIVE_FILES_FROM_ANYONE"}
    not LastEvent.NewValue in AcceptableValues
}

NonCompliantGroups1_3 contains {
    "Name": Group,
    "Value": GetFriendlyValue1_3(LastEvent.NewValue, AcceptableValues)
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "SHARING_OUTSIDE_DOMAIN", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"SHARING_ALLOWED_WITH_WARNING", "SHARING_NOT_ALLOWED",
    "INHERIT_FROM_PARENT", "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES",
    "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING", 
    "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING_MAY_RECEIVE_FILES_FROM_ANYONE"}
    not LastEvent.NewValue in AcceptableValues
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_3, NonCompliantGroups1_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3,
        "NonCompliantGroups": NonCompliantGroups1_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_3) == 0, count(NonCompliantGroups1_3) == 0 }
    Status := (false in Conditions) == false
}

#--

#
# Baseline GWS.DRIVEDOCS.1.4v0.1
#--
NoSuchEvent1_4(TopLevelOU) := true if {
    SettingName := "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"
    Events_A := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events_A) == 0
}

NoSuchEvent1_4(TopLevelOU) := true if {
    SettingName := "SHARING_OUTSIDE_DOMAIN"
    Events_B := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events_B) == 0
}

default NoSuchEvent1_4(_) := false

GetFriendlyValue1_4(Value_A, Value_B, AcceptableValues_A, AcceptableValues_B) :=
"External Sharing is Disabled" if {
    Value_B in AcceptableValues_B
} else := concat("", ["External Sharing is Enabled, ",
    "but Sharing invites to non-google accounts is disabled"]) if {
    Value_A in AcceptableValues_A
} else := "External Sharing is Enabled, and invites can be shared to non-google accounts"

NonCompliantOUs1_4 contains {
    "Name": OU,
    "Value": GetFriendlyValue1_4(LastEvent_A.NewValue,
        LastEvent_B.NewValue, AcceptableValues_A, AcceptableValues_B)
    } if {
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents, "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS", OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsOU(LogEvents, "SHARING_OUTSIDE_DOMAIN", OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    AcceptableValues_A := {"NOT_ALLOWED", "INHERIT_FROM_PARENT"}
    not LastEvent_A.NewValue in AcceptableValues_A
    AcceptableValues_B := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT"}
    not LastEvent_B.NewValue in AcceptableValues_B
}

NonCompliantGroups1_4 contains {
    "Name": Group,
    "Value": GetFriendlyValue1_4(LastEvent_A.NewValue, LastEvent_B.NewValue,
        AcceptableValues_A, AcceptableValues_B)
    } if {
    some Group in utils.GroupsWithEvents
    Events_A := utils.FilterEventsGroup(LogEvents, "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS", Group)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsGroup(LogEvents, "SHARING_OUTSIDE_DOMAIN", Group)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    AcceptableValues_A := {"NOT_ALLOWED", "INHERIT_FROM_PARENT"}
    not LastEvent_A.NewValue in AcceptableValues_A
    AcceptableValues_B := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT"}
    not LastEvent_B.NewValue in AcceptableValues_B
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent1_4(utils.TopLevelOU)
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_4, NonCompliantGroups1_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_4,
        "NonCompliantGroups": NonCompliantGroups1_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent1_4(utils.TopLevelOU)
    Conditions := {count(NonCompliantOUs1_4) == 0, count(NonCompliantGroups1_4) == 0 }
    Status := (false in Conditions) == false
}

#--

#
# Baseline GWS.DRIVEDOCS.1.5v0.1
#--

NonCompliantOUs1_5 contains {
    "Name": OU,
    "Value": "Published web content is visible to anyone with a link. "
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "PUBLISHING_TO_WEB", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("ALLOWED", LastEvent.NewValue) == true
}

NonCompliantGroups1_5 contains {
    "Name": Group,
    "Value": "Published web content is visible to anyone with a link. "
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "PUBLISHING_TO_WEB", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("ALLOWED", LastEvent.NewValue) == true
}


tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "PUBLISHING_TO_WEB", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_5, NonCompliantGroups1_5),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_5,
        "NonCompliantGroups": NonCompliantGroups1_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "PUBLISHING_TO_WEB", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_5) == 0, count(NonCompliantGroups1_5) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.6v0.1
#--
GetFriendlyValue1_6(Value):= "Access Checking is disabled outside of docs and drive"
if { contains("NAMED_PARTIES_ONLY DOMAIN_OR_NAMED_PARTIES INHERIT_FROM_PARENT", Value) == false
} else := "Access Checking is enabled outside of docs and drive."


NonCompliantOUs1_6 contains {
    "Name":OU,
    "Value": GetFriendlyValue1_6(LastEvent.NewValue)
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SHARING_ACCESS_CHECKER_OPTIONS", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("NAMED_PARTIES_ONLY DOMAIN_OR_NAMED_PARTIES INHERIT_FROM_PARENT",
        LastEvent.NewValue) == false
}

NonCompliantGroups1_6 contains {
    "Name":Group,
    "Value": GetFriendlyValue1_6(LastEvent.NewValue)
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "SHARING_ACCESS_CHECKER_OPTIONS", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("NAMED_PARTIES_ONLY DOMAIN_OR_NAMED_PARTIES INHERIT_FROM_PARENT",
        LastEvent.NewValue) == false
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.6v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SHARING_ACCESS_CHECKER_OPTIONS",utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.6v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_6, NonCompliantGroups1_6),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_6,
        "NonCompliantGroups": NonCompliantGroups1_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SHARING_ACCESS_CHECKER_OPTIONS", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_6) == 0, count(NonCompliantGroups1_6) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.7v0.1
#--
GetFriendlyValue1_7(Value):= "Setting is compliant." if {
    Value == "CROSS_DOMAIN_MOVES_BLOCKED"
} else := "Only users inside the organization can distribute content outside of the organization" if {
    Value == "CROSS_DOMAIN_FROM_INTERNAL_ONLY"
} else := "Anyone can distribute content in the organization to outside the organization" if {
    Value == "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"
} else := Value

NonCompliantOUs1_7 contains {
    "Name": OU,
    "Value": GetFriendlyValue1_7(LastEvent.NewValue)
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    SettingValue := "CROSS_DOMAIN_MOVES_BLOCKED INHERIT_FROM_PARENT"
    contains(SettingValue, LastEvent.NewValue) == false
}

NonCompliantGroups1_7 contains {
    "Name": Group,
    "Value": GetFriendlyValue1_7(LastEvent.NewValue)
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    SettingValue := "CROSS_DOMAIN_MOVES_BLOCKED INHERIT_FROM_PARENT"
    contains(SettingValue, LastEvent.NewValue) == false
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.7v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.7v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_7, NonCompliantGroups1_7),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_7, "NonCompliantGroups": NonCompliantGroups1_7},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_7) == 0, count(NonCompliantGroups1_7) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.8v0.1
#--

GetFriendlyValue1_8(Value):= "private to the owner." if {
    Value == "PRIVATE"
} else := "The primary target audience can access the item if they have the link" if {
    Value == "PEOPLE_WITH_LINK"
} else := "The primary target audience can search and find the item." if {
    Value == "PUBLIC"
} else := Value


NonCompliantOUs1_8 contains {
    "Name": OU,
    "Value": concat("", ["When users create items, the default access is set to: ",
        GetFriendlyValue1_8(LastEvent.NewValue)])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "DEFAULT_LINK_SHARING_FOR_NEW_DOCS", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "PRIVATE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}


NonCompliantGroups1_8 contains {
    "Name": Group,
    "Value": concat("", ["When users create items, the default access is set to: ",
        GetFriendlyValue1_8(LastEvent.NewValue)])
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "DEFAULT_LINK_SHARING_FOR_NEW_DOCS", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "PRIVATE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.8v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "DEFAULT_LINK_SHARING_FOR_NEW_DOCS", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.1.8v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_8, NonCompliantGroups1_8),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_8, "NonCompliantGroups": NonCompliantGroups1_8},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "DEFAULT_LINK_SHARING_FOR_NEW_DOCS", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_8) == 0, count(NonCompliantGroups1_8) == 0 }
    Status := (false in Conditions) == false
}
#--

###################
# GWS.DRIVEDOCS.2 #
###################

#
# Baseline GWS.DRIVEDOCS.2.1v0.1
#--
NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": "Members with manager access can override shared drive settings."
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Shared Drive Creation new_team_drive_admin_only", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": "Members with manager access can override shared drive settings."
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "Shared Drive Creation new_team_drive_admin_only", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "Shared Drive Creation new_team_drive_admin_only", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "Shared Drive Creation new_team_drive_admin_only", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs2_1) == 0, count(NonCompliantGroups2_1) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.2.2v0.1
#--
NonCompliantOUs2_2 contains {
    "Name": OU,
    "Value": "Users outside the organization can access files in shared drives"
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_cross_domain_access", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_2 contains {
    "Name": Group,
    "Value": "Users outside the organization can access files in shared drives"
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_cross_domain_access", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.2v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Shared Drive Creation new_team_drive_restricts_cross_domain_access"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.2v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_2, NonCompliantGroups2_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_2, "NonCompliantGroups": NonCompliantGroups2_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Shared Drive Creation new_team_drive_restricts_cross_domain_access"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs2_2) == 0, count(NonCompliantGroups2_2) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.2.3v0.1
#--
NonCompliantOUs2_3 contains {
    "Name": OU,
    "Value": "People who aren't shared drive members cannot be added to files"
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_direct_access", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}
NonCompliantGroups2_3 contains {
    "Name": Group,
    "Value": "People who aren't shared drive members cannot be added to files"
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_direct_access", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}


tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Shared Drive Creation new_team_drive_restricts_direct_access"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_3, NonCompliantGroups2_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_3,
        "NonCompliantGroups": NonCompliantGroups2_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Shared Drive Creation new_team_drive_restricts_direct_access"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
     Conditions := {count(NonCompliantOUs2_3) == 0, count(NonCompliantGroups2_3) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.2.4v0.1
#--
NonCompliantOUs2_4 contains {
    "Name": OU,
    "Value": "Viewers and commenters are allowed to download, print, and copy files"
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_download", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("false", LastEvent.NewValue) == true
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_4 contains {
    "Name": Group,
    "Value": "Viewers and commenters are allowed to download, print, and copy files"
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_download", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("false", LastEvent.NewValue) == true
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_download", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.2.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_4, NonCompliantGroups2_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_4,
        "NonCompliantGroups": NonCompliantGroups2_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents,
        "Shared Drive Creation new_team_drive_restricts_download", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs2_4) == 0, count(NonCompliantGroups2_4) == 0 }
    Status := (false in Conditions) == false
}
#--


###################
# GWS.DRIVEDOCS.3 #
###################

#
# Baseline GWS.DRIVEDOCS.3.1v0.1
#--
NoSuchEvent3_1(TopLevelOU) := true if {
    # No such event...
    SettingName := "Link Security Update Settings allow_less_secure_link_user_restore"
    Events_A := utils.FilterEventsOU(LogEvents, SettingName, TopLevelOU)
    count(Events_A) == 0
}

NoSuchEvent3_1(TopLevelOU) := true if {
    # No such event...
    Events := utils.FilterEventsOU(LogEvents,
        "Link Security Update Settings less_secure_link_option", TopLevelOU)
    count(Events) == 0
}

default NoSuchEvent3_1(_) := false

GetFriendlyValue3_1(Value_B, Value_A) :=
"Remove security update from all impacted files" if {
    Value_B == "REQUIRE_LESS_SECURE_LINKS"
}
else := "Allow users to remove/apply the security update for files they own or manage" if {
    Value_A == "true"
}
NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue3_1(LastEvent_B.NewValue, LastEvent_A.NewValue)
    } if {
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents,
        "Link Security Update Settings allow_less_secure_link_user_restore", OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsOU(LogEvents,
        "Link Security Update Settings less_secure_link_option", OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    true in {
        LastEvent_A.NewValue != "false",
        LastEvent_B.NewValue != "REMOVE_LESS_SECURE_LINKS"
    }
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent3_1(utils.TopLevelOU)
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue" : {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent3_1(utils.TopLevelOU)
    Status := count(NonCompliantOUs3_1) == 0
}
#--

###################
# GWS.DRIVEDOCS.4 #
###################

#
# Baseline GWS.DRIVEDOCS.4.1v0.1
#--
NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": "Drive SDK is Enabled"
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_DRIVE_APPS", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}
NonCompliantGroups4_1 contains {
    "Name": Group,
    "Value": "Drive SDK is Enabled"
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "ENABLE_DRIVE_APPS", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}
tests contains {
    "PolicyId": "GWS.DRIVEDOCS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_DRIVE_APPS", utils.TopLevelOU)
    count(Events) == 0

}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, NonCompliantGroups4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1, "NonCompliantGroups": NonCompliantGroups4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_DRIVE_APPS", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs4_1) == 0, count(NonCompliantGroups4_1) == 0}
    Status := (false in Conditions) == false
}

#--


###################
# GWS.DRIVEDOCS.5 #
###################

#
# Baseline GWS.DRIVEDOCS.5.1v0.1
#--
NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": "Users can install Google Docs add-ons from add-ons store."
    } if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_DOCS_ADD_ONS", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups5_1 contains {
    "Name": Group,
    "Value": "Users can install Google Docs add-ons from add-ons store."
    } if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "ENABLE_DOCS_ADD_ONS", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}
tests contains {
    "PolicyId": "GWS.DRIVEDOCS.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_DOCS_ADD_ONS", utils.TopLevelOU)
    count(Events) == 0

}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, NonCompliantGroups5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1,
        "NonCompliantGroups": NonCompliantGroups5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_DOCS_ADD_ONS", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs5_1) == 0, count(NonCompliantGroups5_1) == 0 }
    Status := (false in Conditions) == false
}
#--

###################
# GWS.DRIVEDOCS.6 #
###################

#
# Baseline GWS.DRIVEDOCS.6.1v0.1
#--
default NoSuchEvent6_1(_) := true

GetFriendlyValue6_1(Value_B, Value_A) :=
"Drive for Desktop is Enabled, but can be used on any device." if {
    Value_B == "false"
}
else := "Drive for Desktop is disabled" if {
    Value_A == "false"
}
else := "Drive for Desktop is enabled, and only on approved devices." if {
    Value_A == "true"
}
NoSuchEvent6_1(TopLevelOU) := false if {
    Events := utils.FilterEventsOU(LogEvents,
        "DriveFsSettingsProto drive_fs_enabled", TopLevelOU)
    count(Events) != 0
}

NoSuchEvent6_1(TopLevelOU) := false if {
    # No such event...
    Events := utils.FilterEventsOU(LogEvents,
        "DriveFsSettingsProto company_owned_only_enabled", TopLevelOU)
    count(Events) != 0
}

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue6_1(LastEvent_B.NewValue, LastEvent_A.NewValue)
    } if {
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents,
        "DriveFsSettingsProto drive_fs_enabled", OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)
    LastEvent_A.NewValue != "DELETE_APPLICATION_SETTING"

    Events_B := utils.FilterEventsOU(LogEvents,
        "DriveFsSettingsProto company_owned_only_enabled", OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)
    LastEvent_B.NewValue != "DELETE_APPLICATION_SETTING"


    LastEvent_A.NewValue == "true"
    LastEvent_B.NewValue != "true"

}

NonCompliantGroups6_1 contains {
    "Name": Group,
    "Value": GetFriendlyValue6_1(LastEvent_B.NewValue, LastEvent_A.NewValue)
    } if {
    some Group in utils.GroupsWithEvents
    Events_A := utils.FilterEventsGroup(LogEvents,
        "DriveFsSettingsProto drive_fs_enabled", Group)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)
    LastEvent_A.NewValue != "DELETE_APPLICATION_SETTING"

    Events_B := utils.FilterEventsGroup(LogEvents,
        "DriveFsSettingsProto company_owned_only_enabled", Group)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)
    LastEvent_B.NewValue != "DELETE_APPLICATION_SETTING"
 
    LastEvent_A.NewValue == "true"
    LastEvent_B.NewValue != "true"


}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.6.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent6_1(utils.TopLevelOU)
}

tests contains {
    "PolicyId": "GWS.DRIVEDOCS.6.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, NonCompliantGroups6_1),
    "ActualValue" : {"NonCompliantOUs": NonCompliantOUs6_1, "NonCompliantGroups": NonCompliantGroups6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent6_1(utils.TopLevelOU)
    Conditions := {count(NonCompliantOUs6_1) == 0, count(NonCompliantGroups6_1) == 0}
    Status := (false in Conditions) == false
}
#--

###################
# GWS.DRIVEDOCS.7 #
###################

#
# Baseline GWS.DRIVEDOCS.7.1v0.1
#--
# not implementable: Need a way to see when a rule is created.
# The fact that a rule is created gets logged but the rule's
# contents are not.
tests contains {
    "PolicyId": "GWS.DRIVEDOCS.7.1v0.1",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--