package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.GMAIL.9.1
#--

test_ImapAccess_Correct_V1 if {
    # Test IMAP and POP Access when there's only one event
    PolicyId := GmailId9_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "IMAP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_POP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "false"},
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

test_ImapAccess_Incorrect_V1 if {
    # Test IMAP and POP Access when there's only one event and it's wrong
    PolicyId := GmailId9_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "IMAP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "ENABLED_FOR_ALL_MAIL_CLIENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_POP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "true"},
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
                 "Value": GetFriendlyValue9_1(true, true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ImapAccess_Incorrect_V2 if {
    # Test IMAP and POP Access when there's only one event and it's wrong
    PolicyId := GmailId9_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "IMAP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "ENABLED_FOR_ALL_MAIL_CLIENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_POP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "true"},
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
                 "Value": GetFriendlyValue9_1(true, true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ImapAccess_Incorrect_V3 if {
    # Test IMAP and POP Access when there are multiple events and the most recent is wrong
    PolicyId := GmailId9_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "IMAP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "ENABLED_FOR_ALL_MAIL_CLIENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_POP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "IMAP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_POP_ACCESS"},
                        {"name": "NEW_VALUE", "value": "false"},
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
                 "Value": GetFriendlyValue9_1(true, false)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
