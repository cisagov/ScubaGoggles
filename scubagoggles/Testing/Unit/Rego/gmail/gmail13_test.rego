package gmail
import future.keywords

import data.utils.FailTestOUNonCompliant

#
# GWS.GMAIL.13.1
#--
test_ExternalReplyWarning_Correct_V1 if {
    # Test Unintended External Reply Warning when there's only one event
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_ExternalReplyWarning_Correct_V2 if {
    # Test Unintended External Reply Warning when there's multiple events and the most recent is correct
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_ExternalReplyWarning_Correct_V3 if {
    # Test Unintended External Reply Warning when there's correct events in multiple OUs
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_ExternalReplyWarning_Correct_V4 if {
    # Test Unintended External Reply Warning when there's correct events in multiple OUs
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_ExternalReplyWarning_Incorrect_V1 if {
    # Test Unintended External Reply Warning when there are no relevant events
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is compliant; manual check recommended."
    ])
}

test_ExternalReplyWarning_Incorrect_V2 if {
    # Test Unintended External Reply Warning when there's only one event and it's wrong
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
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
                  "Value": "Warn for external participants is set to disabled"}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExternalReplyWarning_Incorrect_V3 if {
    # Test Unintended External Reply Warning when there are multiple events and the most recent is wrong
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
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
                  "Value": "Warn for external participants is set to disabled"}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExternalReplyWarning_Incorrect_V4 if {
    # Test Unintended External Reply Warning when there's only one event and it's wrong
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
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
                  "Value": "Warn for external participants is set to disabled"}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExternalReplyWarning_Incorrect_V5 if {
    # Test Unintended External Reply Warning when there are multiple events and the most recent is wrong
    PolicyId := GmailId13_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "OutOfDomainWarningProto disable_untrusted_recipient_warning"
                        },
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
                  "Value": "Warn for external participants is set to disabled"}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
