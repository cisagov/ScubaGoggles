package classroom
import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.FailTestNoEvent
import data.utils.PassTestResult

#
# GWS.CLASSROOM.1.1
#--

test_JoinClassroom_Correct_V1 if {
    # Test enforcing who can join classroom when there's only one event
    PolicyId := ClassroomId1_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto who_can_join_classes"},
                        {"name": "NEW_VALUE", "value": "1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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

test_JoinClassroom_Correct_V2 if {
    # Test enforcing MFA when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := ClassroomId1_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto who_can_join_classes"},
                        {"name": "NEW_VALUE", "value": "1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto who_can_join_classes"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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

test_JoinClassroom_Incorrect_V1 if {
    # Test enforcing who can join classroom when there's only one event and it's wrong
    PolicyId := ClassroomId1_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto who_can_join_classes"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_1("Users in allowlisted domains")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_JoinClassroom_Incorrect_V2 if {
    # Test who can join classroom when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := ClassroomId1_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto who_can_join_classes"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto who_can_join_classes"},
                        {"name": "NEW_VALUE", "value": "1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_1("Users in allowlisted domains")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}


test_JoinClassroom_Incorrect_V3 if {
    # Test enforcing who can join classroom when there no applicable event
    PolicyId := ClassroomId1_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "SOMETHING_ELSE",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}
#--

#
# GWS.CLASSROOM.1.2
#--

test_WhichClasses_Correct_V1 if {
    # Test enforcing which classes users can join when there's only one event
    PolicyId := ClassroomId1_2
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto which_classes_can_users_join"},
                        {"name": "NEW_VALUE", "value": "1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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

test_WhichClasses_Correct_V2 if {
    # Test enforcing which classes users can join when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := ClassroomId1_2
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto which_classes_can_users_join"},
                        {"name": "NEW_VALUE", "value": "1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto which_classes_can_users_join"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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

test_WhichClasses_Incorrect_V1 if {
    # Test enforcing which classes users can join when there's only one event and it's wrong
    PolicyId := ClassroomId1_2
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto which_classes_can_users_join"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_2("Classes in allowlisted domains")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_WhichClasses_Incorrect_V2 if {
    # Test enforcing which classes users can join when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := ClassroomId1_2
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ClassMembershipSettingProto which_classes_can_users_join"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ClassMembershipSettingProto who_can_join_classes",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_2("Classes in allowlisted domains")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_WhichClasses_Incorrect_V3 if {
    # Test enforcing which classes users can join when there no applicable event
    PolicyId := ClassroomId1_2
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "SOMETHING_ELSE",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}
