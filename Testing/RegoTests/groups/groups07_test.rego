package groups
import future.keywords


#
# Policy 1
#--
test_Group_Correct_V1 if {
    # Test one group that is correct
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all groups."
}

test_Group_Correct_V2 if {
    # Test multiple groups that are correct
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
            {
                "email": "admin2@example.org",
                "name": "Group 2",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all groups."
}

test_Group_Correct_V3 if {
    # Test no groups
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "group_settings": [

        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "No groups found in Organization."
}

test_Group_Correct_V4 if {
    # In cases where Groups 6.1 is compliant, Groups 7.1 should be automatically compliant,
    # even if "allowExternalMembers" is set to true.
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto allow_unlisted_groups"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "true",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all groups."
}

test_Group_Correct_V5 if {
    # If Groups 6.1 is compliant test for multiple groups
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto allow_unlisted_groups"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "true",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
             {
                "email": "admin2@example.org",
                "name": "Group 2",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all groups."
}

test_Group_Correct_V6 if {
    # If Groups 6.1 is noncompliant, Groups 7.1 must have restricted access type to be compliant
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Some other value"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all groups."
}

test_Group_Incorrect_V1 if {
    # Test one group that is incorrect
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "true",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Group 1."
}

test_Group_Incorrect_V2 if {
    # Test multiple groups where 1 is incorrect
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
            {
                "email": "admin2@example.org",
                "name": "Group 2",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ALL_MEMBERS_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Group 2."
}

test_Group_Incorrect_V3 if {
    # Test multiple groups where both are incorrect
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "ANYONE_CAN_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
            {
                "email": "admin2@example.org",
                "name": "Group 2",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MANAGERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ALL_MEMBERS_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Group 1, Group 2."
}

test_Group_Incorrect_V4 if {
    # Test multiple groups where both are incorrect in multiple ways
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as { 
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_OWNERS_CAN_VIEW",
                "whoCanModerateMembers": "NONE",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
            {
                "email": "admin2@example.org",
                "name": "Group 2",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "false",
                "whoCanPostMessage": "NONE_CAN_POST",
                "whoCanContactOwner": "ALL_IN_DOMAIN_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Group 1, Group 2."
}

test_Group_Incorrect_V5 if {
    # If ability for groups to be hidden is enabled, then Groups 7.1 should be disabled
    PolicyId := "GWS.GROUPS.7.1v0.1"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "GroupsSharingSettingsProto allow_unlisted_groups"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
        "group_settings": [
            {
                "email": "admin1@example.org",
                "name": "Group 1",
                "whoCanJoin": "CAN_REQUEST_TO_JOIN",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanModerateMembers": "OWNERS_AND_MANAGERS",
                "allowExternalMembers": "true",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "whoCanContactOwner": "ANYONE_CAN_CONTACT"
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Group 1."
}
#--