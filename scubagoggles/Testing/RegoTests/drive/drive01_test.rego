package drive

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.DRIVEDOCS.1.1
#--
test_Sharing_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Sharing_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
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

test_Sharing_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Sharing_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
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

test_Sharing_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
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
                  "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Sharing_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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
                  "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Sharing_Incorrect_V4 if {
    # Test sharing setting when there are multiple OUs and secondary is wrong
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Sharing_Incorrect_V5 if {
    # Test sharing setting when the top OU is not present but there is another
    PolicyId := DriveId1_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--

#
# GWS.DRIVEDOCS.1.2
#--
test_Receiving_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Receiving_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
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

test_Receiving_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Receiving_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Receiving_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
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
                 "Value": EventNonComplianceMessage1_2(EventGetFriendlyValue1_2("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Receiving_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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
                 "Value": EventNonComplianceMessage1_2(EventGetFriendlyValue1_2("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Receiving_Incorrect_V4 if {
    # Test sharing setting when there are multiple OUs, top OU is compliant but secondary isn't
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": EventNonComplianceMessage1_2(EventGetFriendlyValue1_2("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Receiving_Incorrect_V5 if {
    # Test sharing setting when top level OU is not present
    PolicyId := DriveId1_2
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

#
# GWS.DRIVEDOCS.1.3
#--

test_Warnings_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Warnings_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
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

test_Warnings_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Warnings_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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

test_Warnings_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
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
                 "Value": EventNonComplianceMessage1_3(EventGetFriendlyValue1_3("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Warnings_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
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
                 "Value": EventNonComplianceMessage1_3(EventGetFriendlyValue1_3("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Warnings_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": EventNonComplianceMessage1_3(EventGetFriendlyValue1_3("SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Warnings_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := DriveId1_3
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-27-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

#
# GWS.DRIVEDOCS.1.4
#--

test_NonGoogle_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_NonGoogle_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
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

test_NonGoogle_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_NonGoogle_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
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

test_NonGoogle_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ANONYMOUS_PREVIEW"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": EventNonComplianceMessage1_4(EventGetFriendlyValue1_4("ANONYMOUS_PREVIEW",
                                                                                "SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonGoogle_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ANONYMOUS_PREVIEW"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-13-23T00:02:28.672Z"}, # incorrect timestamp??
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-14-24T00:02:28.672Z"}, # incorrect timestamp??
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": EventNonComplianceMessage1_4(EventGetFriendlyValue1_4("ANONYMOUS_PREVIEW",
                                                                                "SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonGoogle_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-24T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": EventNonComplianceMessage1_4(EventGetFriendlyValue1_4("ALLOWED",
                                                                                "SHARING_ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonGoogle_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := DriveId1_4
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

#
# GWS.DRIVEDOCS.1.5
#--

test_Link_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
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

test_Link_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
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

test_Link_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
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

test_Link_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
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

test_Link_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
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
                  "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Link_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
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
                  "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Link_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                  "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Link_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := DriveId1_5
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--

#
# GWS.DRIVEDOCS.1.6
#--
test_SharingChecker_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
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

test_SharingChecker_Correct_V2 if {
    # Test setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "DOMAIN_OR_NAMED_PARTIES"},
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

test_SharingChecker_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
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

test_SharingChecker_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
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

test_SharingChecker_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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
                 "Value": NonComplianceMessage1_6(GetFriendlyValue1_6("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SharingChecker_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
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
                 "Value": NonComplianceMessage1_6(GetFriendlyValue1_6("ALL"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SharingChecker_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "DOMAIN_OR_NAMED_PARTIES"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": NonComplianceMessage1_6(GetFriendlyValue1_6("DOMAIN_OR_NAMED_PARTIES"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SharingChecker_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := DriveId1_6
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

#
# GWS.DRIVEDOCS.1.7
#--

test_CrossDomain_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
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

test_CrossDomain_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
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

test_CrossDomain_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
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

test_CrossDomain_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
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

test_CrossDomain_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
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
                 "Value": NonComplianceMessage1_7("Anyone")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CrossDomain_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and
    # the most recent is wrong, set to anyone can distribute content.
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
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
                 "Value": NonComplianceMessage1_7("Anyone")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CrossDomain_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU,
    # which is set to Anyone in the Organization
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": NonComplianceMessage1_7("Anyone")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CrossDomain_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_CrossDomain_Incorrect_V6 if {
    # Test sharing setting when there are multiple events and
    # the most recent event is wrong, set to only users in the organization
    PolicyId := DriveId1_7
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
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
                 "Value": NonComplianceMessage1_7("Only users inside the organization")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.DRIVEDOCS.1.8
#--

test_Default_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
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

test_Default_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
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

test_Default_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
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

test_Default_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
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

test_Default_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
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
                 "Value": NonComplianceMessage1_8(GetFriendlyValue1_8("PUBLIC"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Default_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
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
                 "Value": NonComplianceMessage1_8(GetFriendlyValue1_8("PUBLIC"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Default_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": NonComplianceMessage1_8(GetFriendlyValue1_8("PUBLIC"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Default_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_Default_Incorrect_V6 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := DriveId1_8
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PEOPLE_WITH_LINK"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                 "Value": NonComplianceMessage1_8(GetFriendlyValue1_8("PEOPLE_WITH_LINK"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
