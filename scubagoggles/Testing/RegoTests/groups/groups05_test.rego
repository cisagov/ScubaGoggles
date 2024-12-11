package groups

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult


#
# Policy 1
#--
test_GroupConservationViewPermission_Correct_V1 if {
    # Test group conversation view permissions when there's only one event
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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

test_GroupConservationViewPermission_Correct_V2 if {
    # Test group conversation view permissions when there's multiple events and the most most recent is correct
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "DOMAIN_USERS"},
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

test_GroupConservationViewPermission_Incorrect_V1 if {
    # Test group conversation view permissions when there are no relevant events
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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

test_GroupConservationViewPermission_Incorrect_V2 if {
    # Test group conversation view permissions when there's only one event and it's wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "DOMAIN_USERS"},
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
                 "Value": NonComplianceMessage5_1("Users in your domain only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupConservationViewPermission_Incorrect_V3 if {
    # Test group conversation view permissions when there's only one event and it's wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MANAGERS"},
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
                 "Value": NonComplianceMessage5_1("Managers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupConservationViewPermission_Incorrect_V4 if {
    # Test group conversation view permissions when there's only one event and it's wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "OWNERS"},
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
                 "Value": NonComplianceMessage5_1("Owners")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupConservationViewPermission_Incorrect_V5 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "DOMAIN_USERS"},
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
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
                 "Value": NonComplianceMessage5_1("Users in your domain only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupConservationViewPermission_Incorrect_V6 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MANAGERS"},
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
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
                 "Value": NonComplianceMessage5_1("Managers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupConservationViewPermission_Incorrect_V7 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "OWNERS"},
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
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
                 "Value": NonComplianceMessage5_1("Owners")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_GroupConservationViewPermission_Incorrect_V8 if {
    # Test group conversation view permissions when there are multiple events
    # and the most recent is wrong
    PolicyId := GroupsId5_1
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
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
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
                 "Value": NonComplianceMessage5_1("Any user")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
