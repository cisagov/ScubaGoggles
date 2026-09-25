package classroom

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodClassroomApi02 := {
    "policies": {
        "topOU": {
            "classroom_api_data_access": {
                "enableApiAccess": false
            },
            "classroom_service_status": {"serviceState": "ENABLED"}
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadClassroomApi02 := {
    "policies": {
        "topOU": {
            "classroom_api_data_access": {
                "enableApiAccess": false
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
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ClassroomAPI_DataAccess_Correct_1 if {
    PolicyId := ClassroomId2_1
    Output := tests with input as GoodClassroomApi02

    PassTestResult(PolicyId, Output)
}

test_ClassroomAPI_DataAccess_Incorrect_1 if {
    PolicyId := ClassroomId2_1
    Output := tests with input as BadClassroomApi02

    failedOU := [{"Name": "fourthOU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(true))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
