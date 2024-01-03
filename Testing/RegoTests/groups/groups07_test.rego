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
    RuleOutput[0].ReportDetails == "Requirement met in all Groups."
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
    RuleOutput[0].ReportDetails == "Requirement met in all Groups."
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
    RuleOutput[0].ReportDetails == "No Groups found in Organization."
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