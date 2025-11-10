package classroom

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodClassroomApi03 := {
    "policies": {
        "topOU": {
            "classroom_roster_import": {
                "rosterImportOption": "OFF"
            },
            "classroom_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadClassroomApi03 := {
    "policies": {
        "topOU": {
            "classroom_roster_import": {
                "rosterImportOption": "OFF"
            },
            "classroom_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
        },
        "thirdOU": {
            "classroom_class_membership": {
                "whoCanJoinClasses": "ANY_GOOGLE_WORKSPACE_USER",
                "whichClassesCanUsersJoin": "CLASSES_IN_ALLOWLISTED_DOMAINS"
            }
        },
        "fourthOU": {
            "classroom_api_data_access": {
                "enableApiAccess": true
            },
            "classroom_roster_import": {
                "rosterImportOption": "ON_CLEVER"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ClassroomAPI_RosterImport_Correct_1 if {
    PolicyId := ClassroomId3_1
    Output := tests with input as GoodClassroomApi03

    PassTestResult(PolicyId, Output)
}

test_ClassroomAPI_DataAccess_Incorrect_1 if {
    PolicyId := ClassroomId3_1
    Output := tests with input as BadClassroomApi03

    failedOU := [{"Name": "fourthOU",
                 "Value": NonComplianceMessage3_1("ON - CLEVER")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
