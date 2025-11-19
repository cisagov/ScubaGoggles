package commoncontrols

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.3.1
#--

test_SSO_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SSO_Correct_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SSO_Correct_V3 if {
    # Test inheritance
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2023-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SSO_Incorrect_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SSO_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SSO_Incorrect_V3 if {
    # Test no relevant events
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SSO_Incorrect_V4 if {
    # Test no relevant events in the top-level OU
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SSO_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := CommonControlsId3_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Second-Level OU",
                  "Value": NonComplianceMessage3_1},
                 {"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.COMMONCONTROLS.3.2
#--

test_SSO_Profiles_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SSO_Profiles_Correct_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SSO_Profiles_Correct_V3 if {
    # Test inheritance
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2023-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_PERFORM_CHALLENGE_SELECTION"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SSO_Profiles_Incorrect_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage3_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SSO_Profiles_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SSO_Profiles_Incorrect_V3 if {
    # Test no relevant events
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SSO_Profiles_Incorrect_V4 if {
    # Test no relevant events in the top-level OU
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SSO_Profiles_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := CommonControlsId3_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2025-03-21T14:35:58.353Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES"},
                        {"name": "SETTING_NAME", "value": "SsoPolicyProto sso_profile_challenge_selection_behavior"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Second-Level OU",
                  "Value": NonComplianceMessage3_2},
                 {"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage3_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--