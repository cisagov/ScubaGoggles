package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi02 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanAllowExternalMembers": false
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
                "ownersCanAllowExternalMembers": true
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_GroupsAPI_ExternalAccess_Correct_1 if {
    PolicyId := GroupsId2_1
    Output := tests with input as GoodGroupsApi02

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_ExternalAccess_Incorrect_1 if {
    PolicyId := GroupsId2_1
    Output := tests with input as BadGroupsApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
