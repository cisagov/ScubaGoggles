package gmail

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.GMAIL.6.1
#--
test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event
    PolicyId := GmailId6_1
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V2 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_1
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V3 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_1
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Correct_V4 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_1
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := GmailId6_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId6_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V4 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_1
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

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage6_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionIdentifyLinksURL_Incorrect_V5 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId6_1
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

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage6_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.GMAIL.6.2
#--

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event and it's correct
    PolicyId := GmailId6_2
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V2 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is correct
    PolicyId := GmailId6_2
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is correct
    PolicyId := GmailId6_2
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionScanLinkedImages_Correct_V4 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is correct
    PolicyId := GmailId6_2
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionScanLinkedImages_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := GmailId6_2
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_LinksExternalImagesProtectionScanLinkedImages_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_2
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionScanLinkedImages_Incorrect_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId6_2
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.6.3
#--

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event
    PolicyId := GmailId6_3
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Correct_V2 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_3
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Correct_V3 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_3
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := GmailId6_3
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_3
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V3 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId6_3
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V4 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_3
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

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage6_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionWarningLinksUntrustedDomains_Incorrect_V5 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId6_3
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

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage6_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.6.4
#--

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V1 if {
    # Test Links and External Images Protections when there's only one event
    PolicyId := GmailId6_4
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V2 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_4
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V3 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_4
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Correct_V4 if {
    # Test Links and External Images Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId6_4
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

    PassTestResult(PolicyId, Output)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V1 if {
    # Test Links and External Images Protections when there are no relevant events
    PolicyId := GmailId6_4
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V2 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_4
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V3 if {
    # Test Links and External Images Protections when there's only one event and it's wrong
    PolicyId := GmailId6_4
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

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage6_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_LinksExternalImagesProtectionFutureRecommendedSettings_Incorrect_V4 if {
    # Test Links and External Images Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId6_4
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
