package gmail

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.GMAIL.7.1
#--

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Correct_V2 if {
    # Test Spoofing and Authentication Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Correct_V3 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Correct_V4 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
        PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Incorrect_V1 if {
    # Test Spoofing and Authentication Protections when there are no relevant events
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Incorrect_V2 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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
                 "Value": NonComplianceMessage7_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Incorrect_V3 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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
                 "Value": NonComplianceMessage7_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Incorrect_V4 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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
                 "Value": NonComplianceMessage7_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionSimilarDomainNameSpoofing_Incorrect_V5 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_1
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
                            ])
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
                                "Spoofing and authentication safety Enable: protect against domain spoofing using ",
                                "similar domain names"
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
                 "Value": NonComplianceMessage7_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.GMAIL.7.2
#--

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Correct_V2 if {
    # Test Spoofing and Authentication Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Correct_V3 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Correct_V4 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Incorrect_V1 if {
    # Test Spoofing and Authentication Protections when there are no relevant events
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Incorrect_V2 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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
                 "Value": NonComplianceMessage7_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Incorrect_V3 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage7_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Incorrect_V4 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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
                 "Value": NonComplianceMessage7_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionEmployeeNameSpoofing_Incorrect_V5 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_2
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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
                            "value":
                                "Spoofing and authentication safety Enable: protect against spoofing of employee names"
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
                 "Value": NonComplianceMessage7_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.7.3
#--

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Correct_V2 if {
    # Test Spoofing and Authentication Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Correct_V3 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Correct_V4 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Incorrect_V1 if {
    # Test Spoofing and Authentication Protections when there are no relevant events
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Incorrect_V2 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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
                 "Value": NonComplianceMessage7_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Incorrect_V3 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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
                 "Value": NonComplianceMessage7_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Incorrect_V4 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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
                 "Value": NonComplianceMessage7_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofing_Incorrect_V5 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_3
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
                            ])
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
                                "Spoofing and authentication safety Enable: protect against inbound emails spoofing ",
                                "your domain"
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
                 "Value": NonComplianceMessage7_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.7.4
#--

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Correct_V2 if {
    # Test Spoofing and Authentication Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Correct_V3 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Correct_V4 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Incorrect_V1 if {
    # Test Spoofing and Authentication Protections when there are no relevant events
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Incorrect_V2 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                 "Value": NonComplianceMessage7_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Incorrect_V3 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                 "Value": NonComplianceMessage7_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Incorrect_V4 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                 "Value": NonComplianceMessage7_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionUnauthenticatedEmail_Incorrect_V5 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_4
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                            "value":
                                "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
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
                 "Value": NonComplianceMessage7_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.7.5
#--

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Correct_V2 if {
    # Test Spoofing and Authentication Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Correct_V3 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Correct_V4 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Incorrect_V1 if {
    # Test Spoofing and Authentication Protections when there are no relevant events
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Incorrect_V2 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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
                 "Value": NonComplianceMessage7_5("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Incorrect_V3 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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
                 "Value": NonComplianceMessage7_5("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Incorrect_V4 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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
                 "Value": NonComplianceMessage7_5("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionInboundEmailDomainSpoofingGroups_Incorrect_V5 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_5
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
                            ])
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
                                "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
                                "spoofing your domain"
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
                 "Value": NonComplianceMessage7_5("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.7.6
#--

test_SpoofingAuthenticationProtection_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_6
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against domain spoofing based on similar ",
                                "domain names action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Quarantine"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against spoofing of employee names action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:26.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against inbound emails spoofing your ",
                                "domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against any unauthenticated emails action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
                                "your domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
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

test_SpoofingAuthenticationProtection_InCorrect_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_6
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against domain spoofing based on similar ",
                                "domain names action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Show warning"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against spoofing of employee names action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:26.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against inbound emails spoofing your ",
                                "domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against any unauthenticated emails action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
                                "your domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Show warning"},
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
                  "Value": GetFriendlyValue7_6("Show warning",
                                               "", "", "", "Show warning")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtection_InCorrect_V2 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_6
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against domain spoofing based on similar ",
                                "domain names action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Show warning"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against spoofing of employee names action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:26.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against inbound emails spoofing your ",
                                "domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against any unauthenticated emails action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
                                "your domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Show warning"},
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
                  "Value": GetFriendlyValue7_6("Show warning",
                                               "", "", "", "Show warning")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.GMAIL.7.7
#--

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Correct_V1 if {
    # Test Spoofing and Authentication Protections when there's only one event
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Correct_V2 if {
    # Test Spoofing and Authentication Protections when there's multiple events and the most recent is correct
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Correct_V3 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Correct_V4 if {
    # Test Spoofing and Authentication Protections when there's correct events in multiple OUs
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
                                "settings"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Incorrect_V1 if {
    # Test Spoofing and Authentication Protections when there are no relevant events
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Incorrect_V2 if {
    # Test Spoofing and Authentication Protections when only one setting
    # doesn't have events
    PolicyId := GmailId7_7
    Output := tests with input as {
"gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against domain spoofing based on similar ",
                                "domain names action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Quarantine"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against spoofing of employee names action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:26.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Protect against inbound emails spoofing your ",
                                "domain action"
                            ])
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value":
                                "Spoofing and authentication safety Protect against any unauthenticated emails action"
                        },
                        {"name": "NEW_VALUE", "value": "Move to spam"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            # Note that "Spoofing and authentication safety Protect your Groups
            # from inbound emails spoofing your domain action" is missing
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Incorrect_V3 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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
                 "Value": NonComplianceMessage7_7("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Incorrect_V4 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage7_7("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Incorrect_V5 if {
    # Test Spoofing and Authentication Protections when there's only one event and it's wrong
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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
                 "Value": NonComplianceMessage7_7("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofingAuthenticationProtectionFutureRecommendedSettings_Incorrect_V6 if {
    # Test Spoofing and Authentication Protections when there are multiple events and the most recent is wrong
    PolicyId := GmailId7_7
    Output := tests with input as {
        "gmail_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": concat("", [
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
                                "settings"
                            ])
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
                                "Spoofing and authentication safety Enable: automatically enables all future added ",
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
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage7_7("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
