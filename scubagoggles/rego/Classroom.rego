package classroom

import future.keywords
import data.utils
import data.utils.PolicyApiInUse

LogEvents := utils.GetEvents("classroom_logs")

ClassroomEnabled(orgunit) := utils.AppEnabled(input.policies, "classroom", orgunit)

###################
# GWS.CLASSROOM.1 #
###################

#
# Baseline GWS.CLASSROOM.1.1
#--

ClassroomId1_1 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.1.1")

LogMessage1_1 := "ClassMembershipSettingProto who_can_join_classes"

GetFriendlyValue1_1(Value) := "Users in your domain only" if {
    Value in {"1", "ANYONE_IN_DOMAIN"}
} else := "Users in allowlisted domains" if {
    Value in {"2", "ANYONE_IN_ALLOWLISTED_DOMAINS"}
} else := "Any Google Workspace user" if {
    Value in {"3", "ANY_GOOGLE_WORKSPACE_USER"}
} else := "Any user" if {
    Value in {"4", "ANYONE"}
} else := Value

Check1_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_1, utils.TopLevelOU)
    count(events) > 0
}

Check1_1_OK if {PolicyApiInUse}

NonComplianceMessage1_1(value) := sprintf("Who can join classes in your domain is set to: %s", [value])

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
    LastEvent.NewValue != "1"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(whoCanJoin))
} if {
    some OU, settings in input.policies
    ClassroomEnabled(OU)
    whoCanJoin := settings.classroom_class_membership.whoCanJoinClasses
    whoCanJoin != "ANYONE_IN_DOMAIN"
}

tests contains {
    "PolicyId": ClassroomId1_1,
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
    "PolicyId": ClassroomId1_1,
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be
    # modified at the group level
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

#
# Baseline GWS.CLASSROOM.1.2
#--

ClassroomId1_2 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.1.2")

LogMessage1_2 := "ClassMembershipSettingProto which_classes_can_users_join"

GetFriendlyValue1_2(Value) := "Classes in your domain only" if {
    Value in {"1", "CLASSES_IN_DOMAIN"}
} else := "Classes in allowlisted domains" if {
    Value in {"2", "CLASSES_IN_ALLOWLISTED_DOMAINS"}
} else := "Any Google Workspace class" if {
    Value in {"3", "ANY_GOOGLE_WORKSPACE_CLASS"}
} else := Value

Check1_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_2, utils.TopLevelOU)
    count(events) > 0
}

Check1_2_OK if {PolicyApiInUse}

NonComplianceMessage1_2(value) := sprintf("Which classes can users in your domain join is set to: %s", [value])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetFriendlyValue1_2(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_2, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetFriendlyValue1_2(whichClasses))
} if {
    some OU, settings in input.policies
    ClassroomEnabled(OU)
    whichClasses := settings.classroom_class_membership.whichClassesCanUsersJoin
    whichClasses != "CLASSES_IN_DOMAIN"
}

tests contains {
    "PolicyId": ClassroomId1_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check1_2_OK
}

tests contains {
    "PolicyId": ClassroomId1_2,
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be
    # modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_2_OK
    Status := count(NonCompliantOUs1_2) == 0
}
#--

###################
# GWS.CLASSROOM.2 #
###################

#
# Baseline GWS.CLASSROOM.2.1
#--

ClassroomId2_1 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.2.1")

LogMessage2_1 := "ApiDataAccessSettingProto api_access_enabled"

GetFriendlyValue2_1(Value) := "unable" if {
    Value in {"false", false}
} else := "able" if {
    Value in {"true", true}
} else := Value

Check2_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_1, utils.TopLevelOU)
    count(events) > 0
}

Check2_1_OK if {PolicyApiInUse}

NonComplianceMessage2_1(value) := sprintf("Users %s to authorize apps to %s",
                                          [value,
                                           "access their Google Classroom data"])

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
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(dataAccessEnabled))
} if {
    some OU, settings in input.policies
    ClassroomEnabled(OU)
    dataAccessEnabled := settings.classroom_api_data_access.enableApiAccess
    dataAccessEnabled != false
}

tests contains {
    "PolicyId": ClassroomId2_1,
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
    "PolicyId": ClassroomId2_1,
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be
    # modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_1_OK
    Status := count(NonCompliantOUs2_1) == 0
}
#--

###################
# GWS.CLASSROOM.3 #
###################

#
# Baseline GWS.CLASSROOM.3.1
#--

ClassroomId3_1 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.3.1")

LogMessage3_1 := "RosterImportSettingsProto sis_integrator"

GetFriendlyValue3_1(Value) := "OFF" if {
    Value in {"SIS_INTEGRATOR_NONE", "OFF"}
} else := "ON - CLEVER" if {
    Value in {"SIS_INTEGRATOR_CLEVER", "ON_CLEVER"}
} else := Value

Check3_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage3_1, utils.TopLevelOU)
    count(events) > 0
}

Check3_1_OK if {PolicyApiInUse}

NonComplianceMessage3_1(value) := sprintf("Roster import is set to: %s", [value])

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
    LastEvent.NewValue != "SIS_INTEGRATOR_NONE"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyValue3_1(rosterImportOption))
} if {
    some OU, settings in input.policies
    ClassroomEnabled(OU)
    rosterImportOption := settings.classroom_roster_import.rosterImportOption
    rosterImportOption != "OFF"
}

tests contains {
    "PolicyId": ClassroomId3_1,
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
    "PolicyId": ClassroomId3_1,
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

###################
# GWS.CLASSROOM.4 #
###################

#
# Baseline GWS.CLASSROOM.4.1
#--

ClassroomId4_1 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.4.1")

LogMessage4_1 := "StudentUnenrollmentSettingsProto who_can_unenroll_students"

GetFriendlyValue4_1(Value) := "Students and teachers" if {
    startswith(Value, "STUDENTS_AND_TEACHERS") == true
} else := "Only teachers" if {
    Value in {"ONLY_TEACHERS_CAN_UNENROLL_STUDENTS", "TEACHERS_ONLY"}
} else := Value

Check4_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage4_1, utils.TopLevelOU)
    count(events) > 0
}

Check4_1_OK if {PolicyApiInUse}

NonComplianceMessage4_1(value) := sprintf("Who can unenroll students from classes is set to: %s", [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value":  NonComplianceMessage4_1(GetFriendlyValue4_1(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage4_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(whoCanUnenroll))
} if {
    some OU, settings in input.policies
    ClassroomEnabled(OU)
    whoCanUnenroll := settings.classroom_student_unenrollment.whoCanUnenrollStudents
    whoCanUnenroll != "TEACHERS_ONLY"
}

tests contains {
    "PolicyId": ClassroomId4_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
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
    "PolicyId": ClassroomId4_1,
    "Criticality": "Shall",
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

###################
# GWS.CLASSROOM.5 #
###################

#
# Baseline GWS.CLASSROOM.5.1
#--

ClassroomId5_1 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.5.1")

LogMessage5_1 := "TeacherPermissionsSettingProto who_can_create_class"

GetFriendlyValue5_1(Value) := "anyone in this domain" if {
    Value in {"1", "ANYONE_IN_DOMAIN"}
} else := "all pending and verified teachers" if {
    Value in {"2", "ALL_PENDING_AND_VERIFIED_TEACHERS"}
} else := Value

Check5_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_1, utils.TopLevelOU)
    count(events) > 0
}

Check5_1_OK if {PolicyApiInUse}

NonComplianceMessage5_1(value) := sprintf("Who can create classes is set to: %s", [value])

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
    LastEvent.NewValue != "3"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1(GetFriendlyValue5_1(whoCanCreate))
} if {
    some OU, settings in input.policies
    ClassroomEnabled(OU)
    whoCanCreate := settings.classroom_teacher_permissions.whoCanCreateClasses
    whoCanCreate != "VERIFIED_TEACHERS_ONLY"
}

tests contains {
    "PolicyId": ClassroomId5_1,
    "Criticality": "Shall",
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
    "PolicyId": ClassroomId5_1,
    "Criticality": "Shall",
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
