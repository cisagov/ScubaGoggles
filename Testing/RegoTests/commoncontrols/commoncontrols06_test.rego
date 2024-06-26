package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.6.1v0.2
#--
test_Separate_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.6.1v0.2"
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
# GWS.COMMONCONTROLS.6.2v0.2
#--
test_Count_Correct_V1 if {
    # 2 super admins
    PolicyId := "GWS.COMMONCONTROLS.6.2v0.2"
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
        "<i>Note: Exceptions are ",
        "allowed for \"break glass\" super admin accounts, ",
        "though we are not able to account for this automatically.</i>"
    ])
}

test_Count_Correct_V2 if {
    # 3 super admins
    PolicyId := "GWS.COMMONCONTROLS.6.2v0.2"
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
        "<i>Note: Exceptions are ",
        "allowed for \"break glass\" super admin accounts, ",
        "though we are not able to account for this automatically.</i>"
    ])
}

test_Count_Correct_V3 if {
    # 4 super admins
    PolicyId := "GWS.COMMONCONTROLS.6.2v0.2"
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
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org, admin3@example.org, ",
        "admin4@example.org. <i>Note: Exceptions are ",
        "allowed for \"break glass\" super admin accounts, ",
        "though we are not able to account for this automatically.</i>"
    ])
}

test_Count_Incorrect_V1 if {
    # 5 super admins
    PolicyId := "GWS.COMMONCONTROLS.6.2v0.2"
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
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org, admin3@example.org, ",
        "admin4@example.org, admin5@example.org. <i>Note: Exceptions are ",
        "allowed for \"break glass\" super admin accounts, ",
        "though we are not able to account for this automatically.</i>"
    ])
}

test_Count_Incorrect_V2 if {
    # 1 super admins
    PolicyId := "GWS.COMMONCONTROLS.6.2v0.2"
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
        "admin1@example.org. <i>Note: Exceptions are ",
        "allowed for \"break glass\" super admin accounts, ",
        "though we are not able to account for this automatically.</i>"
    ])
}
#--