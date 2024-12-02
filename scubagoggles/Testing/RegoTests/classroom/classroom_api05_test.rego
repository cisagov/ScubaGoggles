package classroom

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodClassroomApi05 := {
    "policies": {
        "topOU": {
            "classroom_teacher_permissions": {
                "whoCanCreateClasses": "VERIFIED_TEACHERS_ONLY"
            },
            "classroom_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadClassroomApi05 := {
    "policies": {
        "topOU": {
            "classroom_teacher_permissions": {
                "whoCanCreateClasses": "VERIFIED_TEACHERS_ONLY"
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
            "classroom_teacher_permissions": {
                "whoCanCreateClasses": "ALL_PENDING_AND_VERIFIED_TEACHERS"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ClassroomAPI_Unenrollment_Correct_1 if {
    PolicyId := ClassroomId5_1
    Output := tests with input as GoodClassroomApi05

    PassTestResult(PolicyId, Output)
}

test_ClassroomAPI_Unenrollment_Incorrect_1 if {
    PolicyId := ClassroomId5_1
    Output := tests with input as BadClassroomApi05

    failedOU := [{"Name": "fourthOU",
                 "Value": NonComplianceMessage5_1("all pending and verified teachers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
