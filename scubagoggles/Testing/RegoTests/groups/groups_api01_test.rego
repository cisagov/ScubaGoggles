package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi01 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "collaborationCapability": "DOMAIN_USERS_ONLY"
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

BadGroupsApi01 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "collaborationCapability": "ANYONE_CAN_ACCESS"
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_GroupsAPI_Collaboration_Correct_1 if {
    PolicyId := GroupsId1_1
    Output := tests with input as GoodGroupsApi01

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_Collaboration_Incorrect_1 if {
    PolicyId := GroupsId1_1
    Output := tests with input as BadGroupsApi01

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
