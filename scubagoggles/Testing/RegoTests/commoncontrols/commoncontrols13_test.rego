package commoncontrols
import future.keywords

# Because it takes close to 900 lines to have at least one event for each rule,
# we define a perfect state for the rules once (at the end of this file) then
# modify the perfect state as needed to produce the various conditions we need
# to test for.

#
# GWS.COMMONCONTROLS.13.1
#--
test_Alerts_V1 if {
    # All enabled
    PolicyId := CommonControlsId13_1
    Output := tests with input as {
        # PerfectRules is defined at the end of this file
        "commoncontrols_logs": PerfectRules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, 39 are enabled and 0 are disabled.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V2 if {
    # 1 disabled, the rest enabled
    PolicyId := CommonControlsId13_1
    Rules := json.patch(PerfectRules, [
        {
            "op": "replace",
            # First index (0): the item number
            # Second index (0): the event number
            # Third index (1): the parameter number (1 corresponds to SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE)
            "path": "/items/0/events/0/parameters/1/value",
            "value": "Status changed from ON to OFF."
        }
    ])
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, 38 are enabled and 1 is disabled.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V3 if {
    # 2 disabled, the rest enabled
    PolicyId := CommonControlsId13_1
    Rules := json.patch(PerfectRules, [
        {
            "op": "replace",
            "path": "/items/0/events/0/parameters/1/value",
            "value": "Status changed from ON to OFF."
        },
        {
            "op": "replace",
            "path": "/items/1/events/0/parameters/1/value",
            "value": "Status changed from ON to OFF."
        }
    ])
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, 37 are enabled and 2 are disabled.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V4 if {
    # 1 unknown, the rest enabled
    PolicyId := CommonControlsId13_1
    Rules := json.patch(PerfectRules, [
        {
            "op": "remove",
            "path": "/items/0",
        }
    ])
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, at least 38 are enabled and 0 are disabled.",
        "Unable to determine the state of the 1 remaining required rules.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V5 if {
    # 1 unknown, 1 disabled, the rest enabled
    PolicyId := CommonControlsId13_1
    Rules := json.patch(PerfectRules, [
        {
            "op": "replace",
            "path": "/items/0/events/0/parameters/1/value",
            "value": "Status changed from ON to OFF."
        },
        {
            "op": "remove",
            "path": "/items/1",
        },
    ])
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, at least 37 are enabled and 1 is disabled.",
        "Unable to determine the state of the 1 remaining required rules.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V6 if {
    # All unknown
    PolicyId := CommonControlsId13_1
    Rules := json.patch(PerfectRules, [{"op": "replace", "path": "/items", "value": []}])
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Unable to determine the state of any of the 39 required rules.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V7 if {
    # Just 1 enabled, the rest unknown
    PolicyId := CommonControlsId13_1
    # Delete all but one of the events
    Patches = [{"op": "remove", "path": "/items/0"} | some i in numbers.range(0,37)]
    Rules := json.patch(PerfectRules, Patches)
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, at least 1 is enabled and 0 are disabled.",
        "Unable to determine the state of the 38 remaining required rules.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}

test_Alerts_V8 if {
    # Disable an email only alert
    PolicyId := CommonControlsId13_1
    Patches = [{"op": "replace", "path": "/items/0"} | some i in numbers.range(0,37)]
    Rules := json.patch(PerfectRules, [
        {
            "op": "replace",
            "path": "/items/38/events/0/parameters/1/value",
            "value": "Email notification status changed from ON to OFF."
        },
    ])
    Output := tests with input as {
        "commoncontrols_logs": Rules,
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", [
        "Of the 39 required rules, 38 are enabled and 1 is disabled.",
        "See <a href=\"#alerts\">System Defined Alerts</a> for more details."
    ])
}



PerfectRules := {
    "items": [
        {
            "id": {
                "time": "2022-12-01T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Suspicious device activity"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-02T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User suspended (by admin)"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-03T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Malware message detected post-delivery"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-04T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Google Operations"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-05T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User suspended for spamming through relay"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-06T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User deleted"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-07T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Phishing message detected post-delivery"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-08T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Device compromised"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-09T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Leaked password"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-10T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "[Beta] Client-side encryption service unavailable"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-11T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Domain data export initiated"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-12T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User-reported phishing"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-13T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Account suspension warning"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-14T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Directory sync cancelled due to safeguard threshold exceeded"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-15T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Google Voice configuration problem"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-16T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User's Admin privilege revoked"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-17T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "New user added"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-18T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Suspicious programmatic login"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-19T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User suspended due to suspicious activity"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-20T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Spike in user-reported spam"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-21T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Government-backed attacks"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-22T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Drive settings changed"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-23T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Calendar settings changed"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-24T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User granted Admin privilege"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-25T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Suspended user made active"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-26T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Email settings changed"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-27T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "App Maker Cloud SQL setup"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-28T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Apps outage alert"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-29T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User suspended (Google identity alert)"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-30T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Phishing in inboxes due to bad whitelist"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2022-12-31T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Suspicious message reported"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-01T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "User suspended for spamming"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-02T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Suspicious login"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-03T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Mobile settings changed"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-04T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Gmail potential employee spoofing"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                            "value": "Status changed from OFF to ON."
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "Email notification status unchanged, receivers unchanged."
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-05T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "TLS failure"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "receivers changed from NULL to example example"
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-06T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Exchange journaling failure"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "receivers changed from NULL to example example"
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-07T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Smarthost failure"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "receivers changed from NULL to example example"
                        }
                    ]
                }
            ]
        },
        {
            "id": {
                "time": "2023-01-08T00:02:28.672Z"
            },
            "events": [
                {
                    "parameters": [
                        {
                            "name": "SYSTEM_DEFINED_RULE_NAME",
                            "value": "Rate limited recipient"
                        },
                        {
                            "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                            "value": "receivers changed from NULL to example example"
                        }
                    ]
                }
            ]
        }
    ]
}