package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.12.1v0.1
#--
test_Individual_Correct_V1 if {
    # Test 1 app
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]
             # Note the additional filter: this is because
        # there are actually two tests with the same requirement string for this one,
        # as it has both a testable portion and a not-implementable portion
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement met in all OUs."
}

test_Individual_Correct_V2 if {
    # Test 2 apps
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Pay"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]
             # Note the additional filter: this is because
        # there are actually two tests with the same requirement string for this one,
        # as it has both a testable portion and a not-implementable portion
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement met in all OUs."
}

test_Individual_Correct_V3 if {
    # Test 2 apps, 1 with multiple events
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Pay"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Pay"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]
    # Note the additional filter: this is because
    # there are actually two tests with the same requirement string for this one,
    # as it has both a testable portion and a not-implementable portion
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement met in all OUs."
}

test_Individual_Correct_V4 if {
    # Test no events
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]
    # Note the additional filter: this is because
    # there are actually two tests with the same requirement string for this one,
    # as it has both a testable portion and a not-implementable portion
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["For apps with individual admin control: ",
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable to determine the state ",
        "from the logs, the default setting is compliant; manual check recommended."])
}

test_Individual_Correct_V5 if {
    # Test inheritance
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]
            # Note the additional filter: this is because
            # there are actually two tests with the same requirement string for this one,
            # as it has both a testable portion and a not-implementable portion
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement met in all OUs."
}

test_Individual_Incorrect_V1 if {
    # Test 1 event
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement failed in Test Top-Level OU."
}

test_Individual_Incorrect_V2 if {
    # Test 2 apps
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Pay"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement failed in Test Top-Level OU."
}

test_Individual_Incorrect_V3 if {
    # Test 3 apps, 1 is disabled
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Pay"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Play"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "For apps with individual admin control: Requirement failed in Test Top-Level OU."
}

test_Individual_Inorrect_V4 if {
    # Test no events in top-level OU
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]
             # Note the additional filter: this is because
        # there are actually two tests with the same requirement string for this one,
        # as it has both a testable portion and a not-implementable portion
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["For apps with individual admin control: ",
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable to determine the state ",
        "from the logs, the default setting is compliant; manual check recommended."])}

test_Individual_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Pay"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Play"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
            Result.PolicyId == PolicyId;
            Result.Criticality == "Shall"]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "For apps with individual admin control: ",
        "Requirement failed in Test Second-Level OU, Test Top-Level OU."
    ])
}
#--

#
# GWS.COMMONCONTROLS.12.1v0.1 (not testable portion)
#--

test_Other_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output;
        Result.PolicyId == PolicyId;
        Result.Criticality == "Shall/Not-Implemented"]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "Currently unable to check that Google takeout is disabled ",
        "for services without an individual admin control; manual check recommended."
    ])
}
#--