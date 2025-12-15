package assuredcontrols
import future.keywords
import data.utils.FailTestNoEvent
import data.utils.PassTestResult
import data.utils.FailTestOUNonCompliant

#
# GWS.ASSUREDCONTROLS.1.1
#--

test_Assuredcontrols_1_1_Correct_V1 if {
    # Test 1 event
    PolicyId := AssuredControlsId1_1
    Output := tests with input as {
        "assuredcontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Access Approvals enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Assuredcontrols_1_1_Incorrect_V1 if {
    PolicyId := AssuredControlsId1_1
    Output := tests with input as {
        "assuredcontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Access Approvals enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "Access approvals is disabled."}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Assuredcontrols_1_1_Incorrect_V2 if {
    # test no events
    PolicyId := AssuredControlsId1_1
    Output := tests with input as {
        "assuredcontrols_logs": {"items": []},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--


#
# GWS.ASSUREDCONTROLS.1.2
#--

test_AssuredControls1_2_Correct_1 if {
    PolicyId := AssuredControlsId1_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "access_management_user_scoping": {
                    "accessManagementRegime": "CJIS_IRS_1075_GOOGLE_STAFF"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_AssuredControls1_2_Correct_2 if {
    PolicyId := AssuredControlsId1_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "access_management_user_scoping": {
                    "accessManagementRegime": "US_GOOGLE_STAFF"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_AssuredControls1_2_Incorrect_1 if {
    PolicyId := AssuredControlsId1_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "access_management_user_scoping": {
                    "accessManagementRegime": "PREFERENCE_UNSPECIFIED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    failedOU := [{"Name": "topOU",
                 "Value": "Access management policy is set to No preference"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AssuredControls1_2_Incorrect_2 if {
    PolicyId := AssuredControlsId1_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "access_management_user_scoping": {
                    "accessManagementRegime": "EU_GOOGLE_STAFF"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    failedOU := [{"Name": "topOU",
                 "Value": "Access management policy is set to Access by EU Google staff or via EU virtual desktop"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
