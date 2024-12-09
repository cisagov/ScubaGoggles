package chat

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.CHAT.4.1
#--
test_External_Chat_Sharing_Setting_Correct_V1 if {
    # Test external chat sharing setting when there's only one event - use case #1
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "TRUSTED_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_External_Chat_Sharing_Setting_Correct_V2 if {
    # Test external chat sharing setting when there's only one event - use case #2
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "TRUSTED_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_External_Chat_Sharing_Setting_Correct_V3 if {
    # Test external chat sharing setting when there's multiple events and the most most recent is correct - use case #1
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "TRUSTED_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-22T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-24T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_External_Chat_Sharing_Setting_Correct_V4 if {
    # Test external chat sharing setting when there's multiple events and the most most recent is correct - use case #2
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "TRUSTED_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-23T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-24T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_External_Chat_Sharing_Setting_Incorrect_V1 if {
    # Test external chat sharing setting when there are no relevant events
    PolicyId := ChatId4_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_External_Chat_Sharing_Setting_Incorrect_V2 if {
    # Test external chat sharing setting when there's only one event and it's wrong - use case #1
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "External chat is enabled for all domains"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_External_Chat_Sharing_Setting_Incorrect_V3 if {
    # Test external chat sharing setting when there are multiple events and the most recent is wrong - use case #1
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "TRUSTED_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "External chat is enabled for all domains"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_External_Chat_Sharing_Setting_Incorrect_V4 if {
    # Test there's an event for a secondary OU but not the top-level OU
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_External_Chat_Sharing_Setting_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := ChatId4_1
    Output := tests with input as {
        "chat_logs": {"items": [
               {
                    "id": {"time": "2022-12-21T00:02:28.672Z"},
                    "events": [{
                        "parameters": [
                            {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        ]
                }]
            },
            {
                "id": {"time": "2021-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
             {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto restrictChatToOrganization"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RestrictChatProto externalChatRestriction"},
                        {"name": "NEW_VALUE", "value": "NO_RESTRICTION"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            },
           
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Some other OU",
                 "Value": "External chat is enabled for all domains"},
                 {"Name": "Test Top-Level OU",
                 "Value": "External chat is enabled for all domains"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
