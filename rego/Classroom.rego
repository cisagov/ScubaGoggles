package classroom

import data.utils
import future.keywords

LogEvents := utils.GetEvents("classroom_logs")

###################
# GWS.CLASSROOM.1 #
###################

#
# Baseline GWS.CLASSROOM.1.1v0.1
#--
GetFriendlyValue1_1(Value) := "Users in your domain only" if {
    Value == "1"
} else := "Users in allowlisted domains" if {
    Value == "2"
} else := "Any Google Workspace user" if {
    Value == "3"
} else := "Any user" if {
    Value == "4"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Who can join classes in your domain is set to",
        GetFriendlyValue1_1(LastEvent.NewValue)
    ]) 
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ClassMembershipSettingProto who_can_join_classes", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ClassMembershipSettingProto who_can_join_classes", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ClassMembershipSettingProto who_can_join_classes", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CLASSROOM.1.2v0.1
#--
GetFriendlyValue1_2(Value) := "Classes in your domain only" if {
    Value == "1"
} else := "Classes in allowlisted domains" if {
    Value == "2"
} else := "Any Google Workspace class" if {
    Value == "3"
} else := Value

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Which classes can users in your domain join is set to",
        GetFriendlyValue1_2(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ClassMembershipSettingProto which_classes_can_users_join", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "ClassMembershipSettingProto which_classes_can_users_join"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "ClassMembershipSettingProto which_classes_can_users_join"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--

###################
# GWS.CLASSROOM.2 #
###################

#
# Baseline GWS.CLASSROOM.2.1v0.1
#--
GetFriendlyValue2_1(Value) := "OFF" if {
    Value == "false"
} else := "ON" if {
    Value == "true"
} else := Value

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Data access is set to",
        GetFriendlyValue2_1(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ApiDataAccessSettingProto api_access_enabled", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ApiDataAccessSettingProto api_access_enabled", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ApiDataAccessSettingProto api_access_enabled", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

###################
# GWS.CLASSROOM.3 #
###################

#
# Baseline GWS.CLASSROOM.3.1v0.1
#--
GetFriendlyValue3_1(Value) := "OFF" if {
    Value == "SIS_INTEGRATOR_NONE"
} else := "ON - CLEVER" if {
    Value == "SIS_INTEGRATOR_CLEVER"
} else := Value

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Roster import is set to",
        GetFriendlyValue3_1(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "RosterImportSettingsProto sis_integrator", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SIS_INTEGRATOR_NONE"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "RosterImportSettingsProto sis_integrator", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "RosterImportSettingsProto sis_integrator", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

###################
# GWS.CLASSROOM.4 #
###################

#
# Baseline GWS.CLASSROOM.4.1v0.1
#--
GetFriendlyValue4_1(Value) := "Students and teachers" if {
    Value == "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"
} else := "Only teachers" if {
    Value == "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"
} else := Value

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value":  concat(" ", [
        "Who can unenroll students from classes is set to",
        GetFriendlyValue4_1(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "StudentUnenrollmentSettingsProto who_can_unenroll_students", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "StudentUnenrollmentSettingsProto who_can_unenroll_students"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "StudentUnenrollmentSettingsProto who_can_unenroll_students"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--
