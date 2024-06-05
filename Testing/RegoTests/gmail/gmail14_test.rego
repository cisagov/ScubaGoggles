package gmail
import future.keywords


#
# GWS.GMAIL.14.1v0.2
#--
test_EmailAllowlist_Correct_V1 if {
    # Test Email Allowlists when there's only one event
    PolicyId := "GWS.GMAIL.14.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "EMAIL_SPAM_ALLOWLIST"},
                        {"name": "NEW_VALUE", "value": "[]"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    RuleOutput[0].ReportDetails == concat("", [
        "<span class=setting>Email allowlists are not enabled </span> in ",
        "Test Top-Level Domain."
    ])
}

test_EmailAllowlist_Correct_V2 if {
    # Test Email Allowlists when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.14.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "EMAIL_SPAM_ALLOWLIST"},
                        {"name": "NEW_VALUE", "value": "[]"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "EMAIL_SPAM_ALLOWLIST"},
                        {"name": "NEW_VALUE", "value": "[123.456.7.89]"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    RuleOutput[0].ReportDetails == concat("", [
        "<span class=setting>Email allowlists are not enabled </span> in ",
        "Test Top-Level Domain."
    ])}

test_EmailAllowlist_Incorrect_V1 if {
    # Test Email Allowlists when there are no relevant events
    PolicyId := "GWS.GMAIL.14.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "[]"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs. ",
        "While we are unable to determine the state from the logs, ",
        "the default setting is non-compliant; manual check recommended."
    ])
}

test_EmailAllowlist_Incorrect_V2 if {
    # Test Email Allowlists when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.14.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "EMAIL_SPAM_ALLOWLIST"},
                        {"name": "NEW_VALUE", "value": "[123.456.7.89]"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "<span class=setting>Email allowlists are enabled </span> in Test Top-Level Domain."
}

test_EmailAllowlist_Incorrect_V3 if {
    # Test Email Allowlists when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.14.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "EMAIL_SPAM_ALLOWLIST"},
                        {"name": "NEW_VALUE", "value": "[123.456.7.89]"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "EMAIL_SPAM_ALLOWLIST"},
                        {"name": "NEW_VALUE", "value": "[]"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "<span class=setting>Email allowlists are enabled </span> in Test Top-Level Domain."
}
#--