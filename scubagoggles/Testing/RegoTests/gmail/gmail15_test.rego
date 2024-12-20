package gmail

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.GMAIL.15.1
#--

test_EnhancedPreDeliveryMessageScanning_Correct_V1 if {
    # Test Enhanced Pre-Delivery Message Scanning when there's only one event
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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

    PassTestResult(PolicyId, Output)
}

test_EnhancedPreDeliveryMessageScanning_Correct_V2 if {
    # Test Enhanced Pre-Delivery Message Scanning when there's multiple events and the most recent is correct
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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

    PassTestResult(PolicyId, Output)
}

test_EnhancedPreDeliveryMessageScanning_Correct_V3 if {
    # Test Enhanced Pre-Delivery Message Scanning when there's correct events in multiple OUs
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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

    PassTestResult(PolicyId, Output)
}

test_EnhancedPreDeliveryMessageScanning_Correct_V4 if {
    # Test Enhanced Pre-Delivery Message Scanning when there's correct events in multiple OUs and inherited setting
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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

    PassTestResult(PolicyId, Output)
}

test_EnhancedPreDeliveryMessageScanning_Incorrect_V1 if {
    # Test Enhanced Pre-Delivery Message Scanning when there are no relevant events
    PolicyId := GmailId15_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_EnhancedPreDeliveryMessageScanning_Incorrect_V2 if {
    # Test Enhanced Pre-Delivery Message Scanning when there's only one event and it's wrong
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                 "Value": NonComplianceMessage15_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EnhancedPreDeliveryMessageScanning_Incorrect_V3 if {
    # Test Enhanced Pre-Delivery Message Scanning when there are multiple events and the most recent is wrong
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
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
                 "Value": NonComplianceMessage15_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EnhancedPreDeliveryMessageScanning_Incorrect_V4 if {
    # Test Enhanced Pre-Delivery Message Scanning when there's only one event and it's wrong
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                 "Value": NonComplianceMessage15_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EnhancedPreDeliveryMessageScanning_Incorrect_V5 if {
    # Test Enhanced Pre-Delivery Message Scanning when there are multiple events and the most recent is wrong
    PolicyId := GmailId15_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                            "value": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
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
                 "Value": NonComplianceMessage15_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.GMAIL.15.2
#--

test_Other_Correct_V1 if {
    # Test not implemented
    PolicyId := GmailId15_2
    Output := tests with input as {
        "gmail_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--
