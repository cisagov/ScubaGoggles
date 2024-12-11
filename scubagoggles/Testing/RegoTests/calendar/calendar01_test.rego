package calendar

import future.keywords
import data.utils.FailTestBothNonCompliant
import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.CALENDAR.1.1
#--

test_ExtSharingPrimaryCal_Correct_V1 if {
    # Test external sharing for primary calendars when there's only one event
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V2 if {
    # Test external sharing for primary calendars when there's multiple events and the most most recent is correct
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V3 if {
    # Test external sharing for primary calendars when there's multiple OUs
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V4 if {
    # Test external sharing for primary calendars when there's multiple OUs, and an older event is non-compliant
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V5 if {
    # Test external sharing for primary, inherit from parent
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "something else"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V6 if {
    # Test group
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU OU"},
                        {"name": "GROUP_EMAIL", "value": "group1@example.com"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Incorrect_V1 if {
    # Test external sharing for primary calendars when there are no relevant events
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Incorrect_V2 if {
    # Test external sharing for primary calendars when there's only one event and it's wrong
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_1("Share all information, but outsiders cannot change calendars")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExtSharingPrimaryCal_Incorrect_V3 if {
    # Test external sharing for primary calendars when there are multiple events and the most recent is wrong
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_1("Share all information, but outsiders cannot change calendars")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExtSharingPrimaryCal_Incorrect_V4 if {
    # Test external sharing for primary calendars when there is no event for the Top-level OU
    # but there is one for a different OU
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Incorrect_V5 if {
    # Test external sharing for primary calendars when the Top-Level OU is compliant,
    # but a secondary OU is non-compliant
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage1_1("Share all information, but outsiders cannot change calendars")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExtSharingPrimaryCal_Incorrect_V6 if {
    # Test: top-level OU is compliant but a group is non-compliant
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "group1@example.com"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    Value := "Share all information, but outsiders cannot change calendars"
    failedGroup := [{"Name": "group1@example.com",
                     "Value": NonComplianceMessage1_1(Value)}]
    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}

test_ExtSharingPrimaryCal_Incorrect_V if {
    # Test: top-level OU and a group are non-compliant
    PolicyId := CalendarId1_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "group1@example.com"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    Value := "Share all information, but outsiders cannot change calendars"
    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_1(Value)}]
    failedGroup := [{"Name": "group1@example.com",
                     "Value": NonComplianceMessage1_1(Value)}]
    FailTestBothNonCompliant(PolicyId, Output, failedOU, failedGroup)
}
#--

#
# GWS.CALENDAR.1.2
#--

test_ExtSharingSecondaryCal_Correct_V1 if {
 # Test external sharing for secondary calendars when there's only one event
    PolicyId := CalendarId1_2
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingSecondaryCal_Correct_V2 if {
    # Test external sharing for secondary calendars when there's multiple events and the most most recent is correct
    PolicyId := CalendarId1_2
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingSecondaryCal_Incorrect_V1 if {
    # Test external sharing for secondary calendars when there are no relevant events
    PolicyId := CalendarId1_2
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingSecondaryCal_Incorrect_V2 if {
    # Test external sharing for secondary calendars when there's only one event and it's wrong
    PolicyId := CalendarId1_2
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_2("Share all information, but outsiders cannot change calendars")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExtSharingSecondaryCal_Incorrect_V3 if {
    # Test external sharing for secondary calendars when there are multiple events and the most recent is wrong
    PolicyId := CalendarId1_2
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_WRITE_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage1_2("Share all information, but outsiders cannot change calendars")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
