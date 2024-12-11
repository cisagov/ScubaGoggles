package groups

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# Policy 1
#--
test_GroupAccess_Correct_V1 if {
    # Test group access when there's only one event
    PolicyId := GroupsId1_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto collaboration_policy"},
                        {"name": "NEW_VALUE", "value": "CLOSED"},
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

test_GroupAccess_Correct_V2 if {
    # Test group access when there's multiple events and the most most recent is correct
    PolicyId := GroupsId1_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto collaboration_policy"},
                        {"name": "NEW_VALUE", "value": "CLOSED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto collaboration_policy"},
                        {"name": "NEW_VALUE", "value": "OPEN"},
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

test_GroupsAccess_Incorrect_V1 if {
    # Test group access when there are no relevant events
    PolicyId := GroupsId1_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "CLOSED"},
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

#TODO
test_GroupAccess_Incorrect_V2 if {
    # Test group access when there's only one event and it's wrong
    PolicyId := GroupsId1_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto collaboration_policy"},
                        {"name": "NEW_VALUE", "value": "OPEN"},
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
                 "Value": NonComplianceMessage1_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#TODO
test_GroupAccess_Incorrect_V3 if {
    # Test group access when there are multiple events and the most recent is wrong
    PolicyId := GroupsId1_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto collaboration_policy"},
                        {"name": "NEW_VALUE", "value": "OPEN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto collaboration_policy"},
                        {"name": "NEW_VALUE", "value": "CLOSED"},
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
                 "Value": NonComplianceMessage1_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
