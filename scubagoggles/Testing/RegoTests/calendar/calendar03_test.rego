package calendar

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.CALENDAR.3.1
#--

test_CalInteropMan_Correct_V1 if {
# Test calendar interop management when there's only one event
    PolicyId := CalendarId3_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_EWS_INTEROP"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_CalInteropMan_Correct_V2 if {
    # Test calendar interop management when there's multiple events and the most most recent is correct
    PolicyId := CalendarId3_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_EWS_INTEROP"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_EWS_INTEROP"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_CalInteropMan_Incorrect_V1 if {
    # Test calendar interop management when there are no relevant events
    PolicyId := CalendarId3_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_CalInteropMan_Incorrect_V2 if {
    # Test calendar interop management when there's only one event and it's wrong
    PolicyId := CalendarId3_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_EWS_INTEROP"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CalInteropMan_Incorrect_V3 if {
    # Test calendar interop management when there are multiple events and the most recent is wrong
    PolicyId := CalendarId3_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_EWS_INTEROP"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ENABLE_EWS_INTEROP"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.CALENDAR.3.2
#--

test_OAuth_Correct_V1 if {
    # Not-Implemented
    PolicyId := CalendarId3_2
    Output := tests with input as {
        "calendar_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--
