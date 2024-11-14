package groups

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# Policy 1
#--
test_GroupCreation_Correct_V1 if {
    # Test group creation restrictions when there's only one event
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "ADMIN_ONLY"},
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

test_GroupCreation_Correct_V2 if {
    # Test group creation restrictions when there's multiple events and the most most recent is correct
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "ADMIN_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "USERS_IN_DOMAIN"},
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

test_GroupCreation_Incorrect_V1 if {
    # Test group creation restrictions when there are no relevant events
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "ADMIN_ONLY"},
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

test_GroupCreation_Incorrect_V2 if {
    # Test group creation restrictions when there's only one event and it's wrong
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "USERS_IN_DOMAIN"},
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
                 "Value": NonComplianceMessage4_1("Users in your domain only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupCreation_Incorrect_V3 if {
    # Test group creation restrictions when there are multiple events and the most recent is wrong
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "USERS_IN_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "ADMIN_ONLY"},
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
                 "Value": NonComplianceMessage4_1("Users in your domain only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_GroupCreation_Incorrect_V4 if {
    # Test group creation restrictions when there's only one event and it's wrong
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "WORLD"},
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
                 "Value": NonComplianceMessage4_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupCreation_Incorrect_V5 if {
    # Test group creation restrictions when there are multiple events and the most recent is wrong
    PolicyId := GroupsId4_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "WORLD"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto who_can_create_groups"},
                        {"name": "NEW_VALUE", "value": "ADMIN_ONLY"},
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
                 "Value": NonComplianceMessage4_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
