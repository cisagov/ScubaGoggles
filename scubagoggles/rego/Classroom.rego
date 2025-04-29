package classroom

import future.keywords
import data.utils

ClassroomEnabled(orgunit) := utils.AppEnabled(input.policies, "classroom", orgunit)

###################
# GWS.CLASSROOM.1 #
###################

#
# Baseline GWS.CLASSROOM.1.1
#--

ClassroomId1_1 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.1.1")

GetFriendlyValue1_1(Value) := "Users in your domain only" if {
    Value == "ANYONE_IN_DOMAIN"
} else := "Users in allowlisted domains" if {
    Value == "ANYONE_IN_ALLOWLISTED_DOMAINS"
} else := "Any Google Workspace user" if {
    Value == "ANY_GOOGLE_WORKSPACE_USER"
} else := "Any user" if {
    Value == "ANYONE"
} else := Value

NonComplianceMessage1_1(value) := sprintf("Who can join classes in your domain is set to: %s", [value])

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
    "Prerequisites": [
        "policy/classroom_service_status.serviceState",
        "policy/classroom_class_membership.whoCanJoinClasses"
    ],
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be
    # modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CLASSROOM.1.2
#--

ClassroomId1_2 := utils.PolicyIdWithSuffix("GWS.CLASSROOM.1.2")

GetFriendlyValue1_2(Value) := "Classes in your domain only" if {
    Value == "CLASSES_IN_DOMAIN"
} else := "Classes in allowlisted domains" if {
    Value == "CLASSES_IN_ALLOWLISTED_DOMAINS"
} else := "Any Google Workspace class" if {
    Value == "ANY_GOOGLE_WORKSPACE_CLASS"
} else := Value

NonComplianceMessage1_2(value) := sprintf("Which classes can users in your domain join is set to: %s", [value])

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
    "Prerequisites": [
        "policy/classroom_service_status.serviceState",
        "policy/classroom_class_membership.whichClassesCanUsersJoin"
    ],
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be
    # modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
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

GetFriendlyValue2_1(Value) := "unable" if {
    Value == false
} else := "able" if {
    Value == true
} else := Value

NonComplianceMessage2_1(value) := sprintf("Users %s to authorize apps to %s",
                                          [value,
                                           "access their Google Classroom data"])

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
    "Prerequisites": [
        "policy/classroom_service_status.serviceState",
        "policy/classroom_api_data_access.enableApiAccess"
    ],
    "Criticality": "Shall",
    # Empty list is for noncompliant groups as classroom settings can't be
    # modified at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
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

GetFriendlyValue3_1(Value) := "OFF" if {
    Value == "OFF"
} else := "ON - CLEVER" if {
    Value == "ON_CLEVER"
} else := Value

NonComplianceMessage3_1(value) := sprintf("Roster import is set to: %s", [value])

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
    "Prerequisites": [
        "policy/classroom_service_status.serviceState",
        "policy/classroom_roster_import.rosterImportOption"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
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

GetFriendlyValue4_1(Value) := "Students and teachers" if {
    Value == "STUDENTS_AND_TEACHERS"
} else := "Only teachers" if {
    Value == "TEACHERS_ONLY"
} else := Value

NonComplianceMessage4_1(value) := sprintf("Who can unenroll students from classes is set to: %s", [value])

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
    "Prerequisites": [
        "policy/classroom_service_status.serviceState",
        "policy/classroom_student_unenrollment.whoCanUnenrollStudents"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
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
    Value == "ANYONE_IN_DOMAIN"
} else := "all pending and verified teachers" if {
    Value == "ALL_PENDING_AND_VERIFIED_TEACHERS"
} else := Value

NonComplianceMessage5_1(value) := sprintf("Who can create classes is set to: %s", [value])

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
    "Prerequisites": [
        "policy/classroom_service_status.serviceState",
        "policy/classroom_teacher_permissions.whoCanCreateClasses"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_1) == 0
}
#--
