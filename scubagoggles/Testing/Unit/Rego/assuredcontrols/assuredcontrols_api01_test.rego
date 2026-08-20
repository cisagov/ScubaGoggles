package assuredcontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodAssuredControlsApi01 := {
    "policies": {
        "topOU": {
            "access_approval_axa_user_scoping": {
                "requiresCustomerApproval": true
            },
            "access_management_user_scoping": {
                "accessManagementRegime": "US_GOOGLE_STAFF"
            }
        },
         "nextOU": {
            "access_management_user_scoping": {
                "accessManagementRegime": "CJIS_IRS_1075_GOOGLE_STAFF"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadAssuredControlsApi01 := {
    "policies": {
        "topOU": {
            "access_approval_axa_user_scoping": {
                "requiresCustomerApproval": false
            },
            "access_management_user_scoping": {
                "accessManagementRegime": "EU_GOOGLE_STAFF"
            }
        },
        "nextOU": {
            "access_management_user_scoping": {
                "accessManagementRegime": "PREFERENCE_UNSPECIFIED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_AccessApproval_Correct_1 if {
    PolicyId := AssuredControlsId1_1
    Output := tests with input as GoodAssuredControlsApi01

    PassTestResult(PolicyId, Output)
}

test_AccessApproval_Incorrect_1 if {
    PolicyId := AssuredControlsId1_1
    Output := tests with input as BadAssuredControlsApi01

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AccessManagement_Correct_1 if {
    PolicyId := AssuredControlsId1_2
    Output := tests with input as GoodAssuredControlsApi01

    PassTestResult(PolicyId, Output)
}

test_AccessManagement_Incorrect_1 if {
    PolicyId := AssuredControlsId1_2
    Output := tests with input as BadAssuredControlsApi01

    nextOUMsgValue := GetFriendlyValue1_2("PREFERENCE_UNSPECIFIED")
    topOUMsgValue := GetFriendlyValue1_2("EU_GOOGLE_STAFF")
    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage1_2(nextOUMsgValue)},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage1_2(topOUMsgValue)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
