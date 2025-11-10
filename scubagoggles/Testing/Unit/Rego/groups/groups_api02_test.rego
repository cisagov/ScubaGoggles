package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi02 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "createGroupsAccessLevel": "ADMIN_ONLY"
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
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

BadGroupsApi02 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "createGroupsAccessLevel": "USERS_IN_DOMAIN"
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "groups_for_business_groups_sharing": {
                "createGroupsAccessLevel": "ANYONE_CAN_CREATE"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_GroupsAPI_Creator_Correct_1 if {
    PolicyId := GroupsId2_1
    Output := tests with input as GoodGroupsApi02

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_Creator_Incorrect_1 if {
    PolicyId := GroupsId2_1
    Output := tests with input as BadGroupsApi02

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage2_1("Any user")},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage2_1("Users in your domain only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
