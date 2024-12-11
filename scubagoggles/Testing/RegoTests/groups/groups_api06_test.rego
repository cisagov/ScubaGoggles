package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi06 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanHideGroups": false
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGroupsApi06 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanHideGroups": true
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_GroupsAPI_HiddenGroups_Correct_1 if {
    PolicyId := GroupsId6_1
    Output := tests with input as GoodGroupsApi06

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_HiddenGroups_Incorrect_1 if {
    PolicyId := GroupsId6_1
    Output := tests with input as BadGroupsApi06

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage6_1("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
