package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.15.1
#--
test_AccessControl_Correct_V1 if {
    # Test not implemented
    PolicyId := CommonControlsId15_1
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
# GWS.COMMONCONTROLS.15.2
#--
test_DataProcessing_OUs_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_DataProcessing_OUs_Correct_V2 if {
    # Test inheritance with root and sub OUs
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_DataProcessing_OUs_Incorrect_V1 if {
    # Test incorrect root OU
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Data processing in the region selected for data at rest is set to OFF</li>",
        "</ul>"
    ])
}

test_DataProcessing_OUs_Incorrect_V2 if {
    # Test incorrect second-level OU
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Second-Level OU: Data processing in the region selected for data at rest is set to OFF</li>",
        "</ul>"
    ])
}

test_DataProcessing_OUs_Groups_Incorrect_V1 if {
    # Test for correct root OU but with an incorrect group event
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 1"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following groups are non-compliant:<ul>",
        "<li>Test Group 1: Data processing in the region selected for data at rest is set to OFF</li>",
        "</ul>"
    ])
}

test_DataProcessing_OUs_Groups_Incorrect_V2 if {
    # Test for correct root OU but with incorrect group events
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 1"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 2"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following groups are non-compliant:<ul>",
        "<li>Test Group 1: Data processing in the region selected for data at rest is set to OFF</li>",
        "<li>Test Group 2: Data processing in the region selected for data at rest is set to OFF</li>",
        "</ul>"
    ])
}

test_DataProcessing_OUs_Groups_Incorrect_V3 if {
    # Test for both incorrect OUs and group events
    PolicyId := CommonControlsId15_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2024-10-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 1"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2024-10-19T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "DataProcessingRequirementsProto limit_to_storage_location"},
                        {"name": "GROUP_EMAIL", "value": "Test Group 2"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Data processing in the region selected for data at rest is set to OFF</li>",
        "</ul><br>",
        "The following groups are non-compliant:<ul>",
        "<li>Test Group 1: Data processing in the region selected for data at rest is set to OFF</li>",
        "<li>Test Group 2: Data processing in the region selected for data at rest is set to OFF</li>",
        "</ul>"
    ])
}
#--