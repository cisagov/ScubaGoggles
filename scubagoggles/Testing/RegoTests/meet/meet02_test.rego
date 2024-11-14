package meet

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# Baseline 2 - Policy 1
#--

test_JoinExternalPers_Correct_V1 if {
    # Test meeting access when there's only one event
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_JoinExternalPers_Correct_V2 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_JoinExternalPers_Correct_V3 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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

test_History_Correct_V4 if {
    # Test history setting when set to inherit from parent
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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

test_JoinExternalPers_Correct_V5 if {
    # Test meeting access when there's only one event
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_JoinExternalPers_Correct_V6 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_JoinExternalPers_Correct_V7 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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

test_History_Correct_V8 if {
    # Test history setting when set to inherit from parent
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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

test_JoinExternalPers_Incorrect_V1 if {
    # Test meeting access when there are no relevant events
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_JoinExternalPers_Incorrect_V2 if {
    # Test meeting access when there's only one event and it's wrong
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_JoinExternalPers_Incorrect_V3 if {
    # Test meeting access when there are multiple events and the most recent is wrong
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_JoinExternalPers_Incorrect_V4 if {
    # Test allow user to change history setting when there are multiple OU and a secondary OU is wrong
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_JoinExternalPers_Incorrect_V5 if {
    # Test allow user to change history setting when the primary OU is missing but a different one is present
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_JoinExternalPers_Incorrect_V6 if {
    # Test meeting access when there's only one event and it's wrong
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_JoinExternalPers_Incorrect_V7 if {
    # Test meeting access when there are multiple events and the most recent is wrong
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_JoinExternalPers_Incorrect_V8 if {
    # Test group wrong
    PolicyId := MeetId2_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "SafetyAccessLockProto meetings_allowed_to_join"
                        },
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "SafetyAccessLockProto meetings_allowed_to_join"
                        },
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "GROUP_EMAIL", "value": "group@example.com"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedGroup := [{"Name": "group@example.com",
                     "Value": NonComplianceMessage2_1(GetFriendlyValue2_1("ALL"))}]
    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}
