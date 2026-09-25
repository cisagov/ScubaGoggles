package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGroupsApi04 := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanHideGroups": false,
                "newGroupsAreHidden": false
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
                "ownersCanHideGroups": true,
                "newGroupsAreHidden": false
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "groups_for_business_groups_sharing": {
                "newGroupsAreHidden": true
            }
        },
        "thirdOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanHideGroups": false,
                "newGroupsAreHidden": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGroupsApi04a := {
    "policies": {
        "topOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanHideGroups": false,
                "newGroupsAreHidden": true
            },
            "groups_for_business_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "groups_for_business_groups_sharing": {
                "ownersCanHideGroups": true
            }
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

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage4_1(false, true)},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage4_1(true, false)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupsAPI_HiddenGroups_Incorrect_2 if {
    PolicyId := GroupsId4_1
    Output := tests with input as BadGroupsApi04a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage4_1(true, false)},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage4_1(false, true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
