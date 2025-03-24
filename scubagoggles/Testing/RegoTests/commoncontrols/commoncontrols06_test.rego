package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.6.1
#--
test_Separate_Correct_V1 if {
    # Test not implemented
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

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

#
# GWS.COMMONCONTROLS.6.2
#--
test_Count_Correct_V1 if {
    # 2 super admins
    PolicyId := CommonControlsId6_2
    Output := tests with input as {
        "super_admins": [
            {
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin2@example.org",
                "orgUnitPath": ""
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org. ",
        "<i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Correct_V2 if {
    # 3 super admins
    PolicyId := CommonControlsId6_2
    Output := tests with input as {
        "super_admins": [
            {
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin2@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin3@example.org",
                "orgUnitPath": ""
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org, admin3@example.org. ",
        "<i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Correct_V3 if {
    # 8 super admins
    PolicyId := CommonControlsId6_2
    Output := tests with input as {
        "super_admins": [
            {
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin2@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin3@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin4@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin5@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin6@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin7@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin8@example.org",
                "orgUnitPath": ""
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org, admin3@example.org, admin4@example.org, ",
        "admin5@example.org, admin6@example.org, admin7@example.org, admin8@example.org.",
        " <i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Incorrect_V1 if {
    # 9 super admins
    PolicyId := CommonControlsId6_2
    Output := tests with input as {
        "super_admins": [
            {
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin2@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin3@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin4@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin5@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin6@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin7@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin8@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin9@example.org",
                "orgUnitPath": ""
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org, admin3@example.org, admin4@example.org, admin5@example.org, ",
        "admin6@example.org, admin7@example.org, admin8@example.org, admin9@example.org.",
        " <i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Incorrect_V2 if {
    # 1 super admins
    PolicyId := CommonControlsId6_2
    Output := tests with input as {
        "super_admins": [
            {
                "primaryEmail": "admin1@example.org",
                "orgUnitPath": ""
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org. <i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}
#--
