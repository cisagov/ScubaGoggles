package groups

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# Policy 1
#--
test_GroupIncomingMailPosting_Correct_V1 if {
    # Test group owners' ability to allow incoming mail for posting group messages when there's only one event
    PolicyId := GroupsId3_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
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

test_GroupIncomingMailPosting_Correct_V2 if {
    # Test group owners' ability to allow incoming mail for posting group messages when
    # there's multiple events and the most most recent is correct
    PolicyId := GroupsId3_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
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
                            "value": "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
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

    PassTestResult(PolicyId, Output)
}

test_GroupIncomingMailPosting_Incorrect_V1 if {
    # Test group owners' ability to allow incoming mail for posting group messages when there are no relevant events
    PolicyId := GroupsId3_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_GroupIncomingMailPosting_Incorrect_V2 if {
    # Test group owners' ability to allow incoming mail for posting group messages when
    # there's only one event and it's wrong
    PolicyId := GroupsId3_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
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
                 "Value": NonComplianceMessage3_1("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupIncomingMailPosting_Incorrect_V3 if {
    # Test group owners' ability to allow incoming mail for posting group messages
    # when there are multiple events and the most recent is wrong
    PolicyId := GroupsId3_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
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
                            "value": "GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public"
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
                 "Value": NonComplianceMessage3_1("Yes")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
