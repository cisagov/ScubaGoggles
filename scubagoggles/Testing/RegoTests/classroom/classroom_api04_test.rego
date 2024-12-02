package classroom

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodClassroomApi04 := {
    "policies": {
        "topOU": {
            "classroom_student_unenrollment": {
                "whoCanUnenrollStudents": "TEACHERS_ONLY"
            }
        },
            "classroom_service_status": {"serviceState": "ENABLED"}
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadClassroomApi04 := {
    "policies": {
        "topOU": {
            "classroom_student_unenrollment": {
                "whoCanUnenrollStudents": "TEACHERS_ONLY"
            },
            "classroom_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
        },
        "thirdOU": {
            "classroom_class_membership": {
                "whoCanJoinClasses": "ANY_GOOGLE_WORKSPACE_USER",
                "whichClassesCanUsersJoin": "CLASSES_IN_ALLOWLISTED_DOMAINS"
            },
            "classroom_student_unenrollment": {
                "whoCanUnenrollStudents": "STUDENTS_AND_TEACHERS"
            }
        },
        "fourthOU": {
            "classroom_roster_import": {
                "rosterImportOption": "ON_CLEVER"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ClassroomAPI_Unenrollment_Correct_1 if {
    PolicyId := ClassroomId4_1
    Output := tests with input as GoodClassroomApi04

    PassTestResult(PolicyId, Output)
}

test_ClassroomAPI_Unenrollment_Incorrect_1 if {
    PolicyId := ClassroomId4_1
    Output := tests with input as BadClassroomApi04

    failedOU := [{"Name": "thirdOU",
                 "Value": NonComplianceMessage4_1("Students and teachers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
