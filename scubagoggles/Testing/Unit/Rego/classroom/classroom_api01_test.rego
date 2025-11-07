package classroom

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodClassroomApi01 := {
    "policies": {
        "topOU": {
            "classroom_class_membership": {
                "whoCanJoinClasses": "ANYONE_IN_DOMAIN",
                "whichClassesCanUsersJoin": "CLASSES_IN_DOMAIN"
            },
            "classroom_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
        },
        "thirdOU": {
            "security_session_controls": {
                "webSessionDuration": "700m"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadClassroomApi01 := {
    "policies": {
        "topOU": {
            "classroom_class_membership": {
                "whoCanJoinClasses": "ANYONE_IN_DOMAIN",
                "whichClassesCanUsersJoin": "CLASSES_IN_ALLOWLISTED_DOMAINS"
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
        },
        "fourthOU": {
            "security_session_controls": {
                "webSessionDuration": "12H"
            },
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ClassroomAPI_JoinClassroom_Correct_1 if {
    PolicyId := ClassroomId1_1
    Output := tests with input as GoodClassroomApi01

    PassTestResult(PolicyId, Output)
}

test_ClassroomAPI_JoinClassroom_Incorrect_1 if {
    PolicyId := ClassroomId1_1
    Output := tests with input as BadClassroomApi01

    failedOU := [{"Name": "thirdOU",
                 "Value": NonComplianceMessage1_1("Any Google Workspace user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ClassroomAPI_JoinClasses_Correct_1 if {
    PolicyId := ClassroomId1_2
    Output := tests with input as GoodClassroomApi01

    PassTestResult(PolicyId, Output)
}

test_ClassroomAPI_JoinClasses_Incorrect_1 if {
    PolicyId := ClassroomId1_2
    Output := tests with input as BadClassroomApi01

    whichClasses := "Classes in allowlisted domains"
    failedOU := [{"Name": "thirdOU",
                 "Value": NonComplianceMessage1_2(whichClasses)},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_2(whichClasses)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
