package groups

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# Baseline GWS.GROUPS.1.1
#--
GoodGroupsApi1_1 := {
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

BadGroupsApi1_1 := {
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
    Output := tests with input as GoodGroupsApi1_1

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_Collaboration_Incorrect_1 if {
    PolicyId := GroupsId1_1
    Output := tests with input as BadGroupsApi1_1

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# Baseline GWS.GROUPS.1.2
#--

GoodGroupsApi1_2 := {
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

BadGroupsApi1_2 := {
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
    PolicyId := GroupsId1_2
    Output := tests with input as GoodGroupsApi1_2

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_ExternalAccess_Incorrect_1 if {
    PolicyId := GroupsId1_2
    Output := tests with input as BadGroupsApi1_2

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_2("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# Baseline GWS.GROUPS.1.3
#--

GoodGroupsApi1_3 := {
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

BadGroupsApi1_3 := {
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
    PolicyId := GroupsId1_3
    Output := tests with input as GoodGroupsApi1_3

    PassTestResult(PolicyId, Output)
}

test_GroupsAPI_ExternalEmail_Incorrect_1 if {
    PolicyId := GroupsId1_3
    Output := tests with input as BadGroupsApi1_3

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_3("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
