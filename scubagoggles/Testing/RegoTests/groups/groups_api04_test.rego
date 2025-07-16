package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi04 := {
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

BadGroupsApi04 := {
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
    PolicyId := GroupsId4_1
    Output := tests with input as GoodGroupsApi04

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_HiddenGroups_Incorrect_1 if {
    PolicyId := GroupsId4_1
    Output := tests with input as BadGroupsApi04

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage4_1("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
