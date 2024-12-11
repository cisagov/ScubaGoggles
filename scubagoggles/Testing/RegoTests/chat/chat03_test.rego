package chat

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.CHAT.3.1
#--
test_Space_History_Setting_Correct_V1 if {
    # Test space history setting when there's only one event - use case #1
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "DEFAULT_ON_THE_RECORD"},
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

test_Space_History_Setting_Correct_V2 if {
    # Test space history setting when there's only one event - use case #2
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_ON_THE_RECORD"},
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

test_Space_History_Setting_Correct_V3 if {
    # Test space history setting when there's multiple events and the most most recent is correct - use case #1
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "DEFAULT_ON_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "DEFAULT_OFF_THE_RECORD"},
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

test_Space_History_Setting_Correct_V4 if {
    # Test space history setting when there's multiple events and the most most recent is correct - use case #2
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_ON_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_OFF_THE_RECORD"},
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

test_Space_History_Setting_Incorrect_V1 if {
    # Test space history setting when there are no relevant events
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_ON_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_Space_History_Setting_Incorrect_V2 if {
    # Test space history setting when there's only one event and it's wrong - use case #1
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_OFF_THE_RECORD"},
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
                 "Value": NonComplianceMessage3_1("ALWAYS OFF")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Space_History_Setting_Incorrect_V3 if {
    # Test space history setting when there's only one event and it's wrong - use case #2
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "DEFAULT_OFF_THE_RECORD"},
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
                 "Value": NonComplianceMessage3_1("OFF by default")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Space_History_Setting_Incorrect_V4 if {
    # Test space history setting when there are multiple events and the most recent is wrong - use case #1
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "DEFAULT_OFF_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "DEFAULT_ON_THE_RECORD"},
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
                 "Value": NonComplianceMessage3_1("OFF by default")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Space_History_Setting_Incorrect_V5 if {
    # Test space history setting when there are multiple events and the most recent is wrong - use case #2
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_OFF_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_ON_THE_RECORD"},
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
                 "Value": NonComplianceMessage3_1("ALWAYS OFF")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Space_History_Setting_Incorrect_V6 if {
    # Test there's an event for a secondary OU but not the top-level OU
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_OFF_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_Space_History_Setting_Incorrect_V7 if {
    # Test multiple OUs
    PolicyId := ChatId3_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_OFF_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RoomOtrSettingsProto otr_state"},
                        {"name": "NEW_VALUE", "value": "ALWAYS_OFF_THE_RECORD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Some other OU",
                 "Value": NonComplianceMessage3_1("ALWAYS OFF")},
                 {"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_1("ALWAYS OFF")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
