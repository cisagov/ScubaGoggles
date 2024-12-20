package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi03 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanAllowIncomingMailFromPublic": false
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

BadGroupsApi03 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanAllowIncomingMailFromPublic": true
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_GroupsAPI_ExternalEmail_Correct_1 if {
    PolicyId := GroupsId3_1
    Output := tests with input as GoodGroupsApi03

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_ExternalEmail_Incorrect_1 if {
    PolicyId := GroupsId3_1
    Output := tests with input as BadGroupsApi03

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_1("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
