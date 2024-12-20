package gmail

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestNonCompliant
import data.utils.PassTestResultWithMessage

#
# GWS.GMAIL.14.1
#--

test_EmailAllowlist_Correct_V1 if {
    # Test Email Allowlists when there's only one event
    PolicyId := GmailId14_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GmailIpWhitelistSpamFilteringProto is_empty"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level Domain"
        }
    }

    Message := NonComplianceMessage14_1(GetFriendlyValue14_1("true"),
                                        "Test Top-Level Domain")
    PassTestResultWithMessage(PolicyId, Output, Message)
}

test_EmailAllowlist_Correct_V2 if {
    # Test Email Allowlists when there's multiple events and the most recent is correct
    PolicyId := GmailId14_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GmailIpWhitelistSpamFilteringProto is_empty"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GmailIpWhitelistSpamFilteringProto is_empty"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level Domain"
        }
    }

    Message := NonComplianceMessage14_1(GetFriendlyValue14_1("true"),
                                        "Test Top-Level Domain")
    PassTestResultWithMessage(PolicyId, Output, Message)
}

test_EmailAllowlist_Incorrect_V1 if {
    # Test Email Allowlists when there are no relevant events
    PolicyId := GmailId14_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level Domain"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level Domain", true)
}

test_EmailAllowlist_Incorrect_V2 if {
    # Test Email Allowlists when there's only one event and it's wrong
    PolicyId := GmailId14_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GmailIpWhitelistSpamFilteringProto is_empty"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level Domain"
        }
    }

    FailTestNonCompliant(PolicyId,
                         Output,
                         NonComplianceMessage14_1(GetFriendlyValue14_1("false"),
                                                  "Test Top-Level Domain"))
}

test_EmailAllowlist_Incorrect_V3 if {
    # Test Email Allowlists when there are multiple events and the most recent is wrong
    PolicyId := GmailId14_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GmailIpWhitelistSpamFilteringProto is_empty"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GmailIpWhitelistSpamFilteringProto is_empty"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level Domain"
        },
    }

    FailTestNonCompliant(PolicyId,
                         Output,
                         NonComplianceMessage14_1(GetFriendlyValue14_1("false"),
                                                  "Test Top-Level Domain"))
}
#--
