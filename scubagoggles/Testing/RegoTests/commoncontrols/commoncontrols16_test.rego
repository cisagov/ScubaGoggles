package commoncontrols

import future.keywords
import data.utils.FailTestBothNonCompliant
import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.16.1
#--

test_Unlisted_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId16_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Unlisted_Correct_V2 if {
    # Test inheritance
    PolicyId := CommonControlsId16_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Unlisted_Incorrect_V1 if {
    PolicyId := CommonControlsId16_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage16_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Unlisted_Incorrect_V2 if {
    # Test no events
    PolicyId := CommonControlsId16_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--

#
# GWS.COMMONCONTROLS.16.2
#--

test_EarlyAccessApps_OUs_Correct_V1 if {
    # Test 1 correct event
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-15T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_EarlyAccessApps_OUs_Correct_V2 if {
    # Test inheritance with root and sub OUs
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_EarlyAccessApps_OUs_Incorrect_V1 if {
    # Test incorrect root OU
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-05-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage16_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EarlyAccessApps_OUs_Incorrect_V2 if {
    # Test incorrect second-level OU
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Second-Level OU",
                  "Value": NonComplianceMessage16_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EarlyAccessApps_OUs_Correct_Groups_Incorrect_V1 if {
    # Test for correct root OU but with an incorrect group event
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 1"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedGroup := [{"Name": "Test Group 1",
                     "Value": NonComplianceMessage16_2}]
    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}

test_EarlyAccessApps_OUs_Correct_Groups_Incorrect_V2 if {
    # Test for correct root OU but with incorrect group events
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 1"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 2"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedGroup := [{"Name": "Test Group 1",
                     "Value": NonComplianceMessage16_2},
                    {"Name": "Test Group 2",
                     "Value": NonComplianceMessage16_2}]
    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}

test_EarlyAccessApps_OUs_Groups_Incorrect_V1 if {
    # Test for both incorrect OUs and group events
    PolicyId := CommonControlsId16_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 1"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Early Access Apps"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 2"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }


    failedGroup := [{"Name": "Test Group 1",
                     "Value": NonComplianceMessage16_2},
                    {"Name": "Test Group 2",
                     "Value": NonComplianceMessage16_2}]
    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage16_2}]
    FailTestBothNonCompliant(PolicyId, Output, failedOU, failedGroup)
}
#--
