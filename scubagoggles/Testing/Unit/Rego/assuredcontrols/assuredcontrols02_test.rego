package assuredcontrols
import future.keywords
import data.utils.FailTestNoEvent
import data.utils.PassTestResult
import data.utils.FailTestOUNonCompliant

#
# GWS.ASSUREDCONTROLS.2.1
#--

BaseInput := {
    "assuredcontrols_logs": {"items": [
        {
            "id": {"time": "2022-01-20T00:02:28.662Z"},
            "events": [{
                "parameters": [
                    {"name": "SETTING_NAME", "value":
                        "CalendarNonRegionalizedFunctionalityStateSettingsProto state"},
                    {"name": "NEW_VALUE", "value": "DISABLED"},
                    {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                ]
            }]
        },
        {
            "id": {"time": "2022-02-20T00:02:28.662Z"},
            "events": [{
                "parameters": [
                    {"name": "SETTING_NAME", "value":
                        "DocsNonRegionalizedFunctionalityStateSettingsProto state"},
                    {"name": "NEW_VALUE", "value": "DISABLED"},
                    {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                ]
            }]
        },
        {
            "id": {"time": "2022-03-20T00:02:28.662Z"},
            "events": [{
                "parameters": [
                    {"name": "SETTING_NAME", "value":
                        "GmailNonRegionalizedFunctionalityStateSettingsProto state"},
                    {"name": "NEW_VALUE", "value": "DISABLED"},
                    {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                ]
            }]
        },
        {
            "id": {"time": "2022-04-20T00:02:28.662Z"},
            "events": [{
                "parameters": [
                    {"name": "SETTING_NAME", "value":
                        "ChatNonRegionalizedFunctionalityStateSettingsProto state"},
                    {"name": "NEW_VALUE", "value": "DISABLED"},
                    {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                ]
            }]
        },
        {
            "id": {"time": "2022-05-20T00:02:28.662Z"},
            "events": [{
                "parameters": [
                    {"name": "SETTING_NAME", "value":
                        "MeetNonRegionalizedFunctionalityStateSettingsProto state"},
                    {"name": "NEW_VALUE", "value": "DISABLED"},
                    {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                ]
            }]
        },
        {
            "id": {"time": "2022-06-20T00:02:28.662Z"},
            "events": [{
                "parameters": [
                    {"name": "SETTING_NAME", "value":
                        "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                    {"name": "NEW_VALUE", "value": "DISABLED"},
                    {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                ]
            }]
        },
    ]},
    "tenant_info": {
        "topLevelOU": "Test Top-Level OU"
    }
}

test_Assuredcontrols2_1_Correct_V1 if {
    PolicyId := AssuredControlsId2_1
    Output := tests with input as BaseInput
    PassTestResult(PolicyId, Output)
}

test_Assuredcontrols2_1_Incorrect_V1 if {
    # 1 bad
    PolicyId := AssuredControlsId2_1
    Input := json.patch(BaseInput, [
        {
            "op": "replace",
            # First index (0): the item number
            # Second index (0): the event number
            # Third index (1): the parameter number (1 corresponds to NEW_VALUE)
            "path": "/assuredcontrols_logs/items/0/events/0/parameters/1/value",
            "value": "ENABLED"
        }
    ])
    Output := tests with input as Input
    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "Features that may process data across multiple regions are enabled for Calendar"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Assuredcontrols2_1_Incorrect_V2 if {
    # 2 bad
    PolicyId := AssuredControlsId2_1
    Input := json.patch(BaseInput, [
        {
            "op": "replace",
            "path": "/assuredcontrols_logs/items/0/events/0/parameters/1/value",
            "value": "ENABLED"
        },
        {
            "op": "replace",
            "path": "/assuredcontrols_logs/items/1/events/0/parameters/1/value",
            "value": "ENABLED"
        }
    ])
    Output := tests with input as Input
    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "Features that may process data across multiple regions are enabled for Calendar, Docs"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Assuredcontrols2_1_Incorrect_V3 if {
    # 1 unknown
    PolicyId := AssuredControlsId2_1
    Input := json.patch(BaseInput, [
        {
            "op": "remove",
            "path": "/assuredcontrols_logs/items/0",
        },
    ])
    Output := tests with input as Input
    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_Assuredcontrols2_1_Incorrect_V4 if {
    # All unknown
    PolicyId := AssuredControlsId2_1
    Input := json.patch(BaseInput, [
        {
            "op": "replace",
            "path": "/assuredcontrols_logs/items",
            "value": []
        }
    ])
    Output := tests with input as Input
    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--
