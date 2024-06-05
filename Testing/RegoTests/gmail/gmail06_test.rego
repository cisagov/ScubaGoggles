package gmail
import future.keywords


#
# GWS.GMAIL.6.1v0.2
#--
test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V2 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
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
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V3 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:03:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:04:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V4 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Identify links behind shortened URLs is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
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
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Identify links behind shortened URLs is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V4 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
        "Identify links behind shortened URLs is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V5 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.6.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: identify links behind shortened URLs"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
        "Identify links behind shortened URLs is disabled</li></ul>"])
}
#--

#
# GWS.GMAIL.6.2v0.2
#--

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event and it's correct
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V2 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
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
                            "value": "Links and external images safety Enable: scan linked images"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
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
                            "value": "Links and external images safety Enable: scan linked images"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V4 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionScanLinkedImages_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_LinksExternalImagesProtectionScanLinkedImages_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Scan linked images is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionScanLinkedImages_Incorrect_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.6.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Links and external images safety Enable: scan linked images"
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
                            "value": "Links and external images safety Enable: scan linked images"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Scan linked images is disabled</li></ul>"])
}

#
# GWS.GMAIL.6.3v0.2
#--

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Correct_V2 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
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
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Correct_V3 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
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
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Show warning prompt for click on links to untrusted domains is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", ["Links and external images safety Enable: ",
                                        "show warning prompt for click on links to unstrusted domains"])
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
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Show warning prompt for click on links to untrusted domains is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V4 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", ["Links and external images safety Enable: ",
                                        "show warning prompt for click on links to unstrusted domains"])
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
        "Show warning prompt for click on links to untrusted domains is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V5 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.6.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", ["Links and external images safety Enable: ",
                                        "show warning prompt for click on links to unstrusted domains"])
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: show warning prompt for click on links to ",
                                "unstrusted domains"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
        "Show warning prompt for click on links to untrusted domains is disabled</li></ul>"])
}

#
# GWS.GMAIL.6.4v0.2
#--

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V2 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V3 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V4 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Apply future recommended settings automatically is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V3 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
        "Apply future recommended settings automatically is disabled</li></ul>"])
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V4 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GMAIL.6.4v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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
                            "value": concat("", [
                                "Links and external images safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Apply future recommended settings automatically is disabled</li></ul>"])
}