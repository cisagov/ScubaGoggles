package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.10.1
#--

test_AccessControl_Correct_V1 if {
    # Test not implemented
    PolicyId := CommonControlsId10_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_google_services": {
                    "services": [
                        {
                            "scopesGroup": "DRIVE_ALL",
                            "isEnabled": false
                        }
                    ]
                }
            }
        },
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

#
# GWS.COMMONCONTROLS.10.2
#--

test_HighRiskServices_Correct_1 if {
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_google_services": {
                    "services": [
                        {
                            "scopesGroup": "DRIVE_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GMAIL_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLASSROOM_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CHAT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "MEET",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CALENDAR_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CONTACTS_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GSUITE_ADMIN_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "VAULT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_PLATFORM",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_BILLING",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_ML",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_RUNTIME",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_API",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "TASKS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GROUPS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_SEARCH",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "SIGN_IN",
                            "isEnabled": false
                        }
                    ]
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    
    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_HighRiskServices_Incorrect_1 if {
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_google_services": {
                    "services": [
                        {
                            "scopesGroup": "DRIVE_HIGH_RISK",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GMAIL_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLASSROOM_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CHAT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "MEET",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CALENDAR_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CONTACTS_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GSUITE_ADMIN_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "VAULT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_PLATFORM",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_BILLING",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_ML",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_RUNTIME",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_API",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "TASKS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GROUPS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_SEARCH",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "SIGN_IN",
                            "isEnabled": false
                        }
                    ]
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "The following services allow access: DRIVE."
}

test_HighRiskServices_Incorrect_2 if {
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_google_services": {
                    "services": [
                        {
                            "scopesGroup": "DRIVE_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GMAIL_HIGH_RISK",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLASSROOM_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CHAT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "MEET",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CALENDAR_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CONTACTS_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GSUITE_ADMIN_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "VAULT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_PLATFORM",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_BILLING",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_ML",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_RUNTIME",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_API",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "TASKS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GROUPS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_SEARCH",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "SIGN_IN",
                            "isEnabled": false
                        }
                    ]
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "The following services allow access: GMAIL."
}

test_HighRiskServices_Incorrect_3 if {
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_google_services": {
                    "services": [
                        {
                            "scopesGroup": "DRIVE_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GMAIL_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLASSROOM_HIGH_RISK",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CHAT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "MEET",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CALENDAR_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CONTACTS_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GSUITE_ADMIN_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "VAULT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_PLATFORM",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_BILLING",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_ML",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_RUNTIME",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_API",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "TASKS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GROUPS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_SEARCH",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "SIGN_IN",
                            "isEnabled": false
                        }
                    ]
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "The following services allow access: CLASSROOM."
}

test_HighRiskServices_Incorrect_4 if {
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_google_services": {
                    "services": [
                        {
                            "scopesGroup": "DRIVE_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GMAIL_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLASSROOM_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CHAT_HIGH_RISK",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "MEET",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CALENDAR_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CONTACTS_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GSUITE_ADMIN_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "VAULT_ALL",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_PLATFORM",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_BILLING",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_ML",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_RUNTIME",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "APPS_SCRIPT_API",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "TASKS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "GROUPS",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "CLOUD_SEARCH",
                            "isEnabled": false
                        },
                        {
                            "scopesGroup": "SIGN_IN",
                            "isEnabled": false
                        }
                    ]
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }
    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "The following services allow access: CHAT."
}

#
# GWS.COMMONCONTROLS.10.3
#--

test_TrustInternalApps_Correct_1 if {
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_internal_apps": {"trustInternalApps": false}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)    
}

test_TrustInternalApps_Incorrect_1 if {
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_internal_apps": {"trustInternalApps": true}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage10_3}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.COMMONCONTROLS.10.4
#--

test_ThirdPartyApps_Correct_1 if {
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_unconfigured_third_party_apps": {
                    "accessLevel": "BLOCK_ALL_SCOPES",
                    "accessLevelUnder18": "UNDERAGE_UBER_BLOCK_UNSPECIFIED"
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)    
}

test_ThirdPartyApps_Incorrect_1 if {
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_unconfigured_third_party_apps": {
                    "accessLevel": "UNSPECIFIED_UBER_BLOCK",
                    "accessLevelUnder18": "UNDERAGE_UBER_BLOCK_UNSPECIFIED"
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": concat("", ["Unconfigured third-party app access is set to:", 
                  " Allow users to access any third-party apps."])}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ThirdPartyApps_Incorrect_2 if {
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "policies": {
            "topOU": {
                "api_controls_unconfigured_third_party_apps": {
                    "accessLevel": "ALLOW_SIGN_IN_SCOPES_ONLY",
                    "accessLevelUnder18": "UNDERAGE_UBER_BLOCK_UNSPECIFIED"
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": concat("", ["Unconfigured third-party app access is set to:",
                  " Allow users to access third-party apps that only request basic info needed for Sign in with Google."])}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#
# GWS.COMMONCONTROLS.10.5
#--

test_LessSecureApps_Correct_1 if {
    PolicyId := CommonControlsId10_5
    Output := tests with input as {
        "policies": {
            "topOU": {
                "security_less_secure_apps": {"allowLessSecureApps": false}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_LessSecureApps_Incorrect_1 if {
    PolicyId := CommonControlsId10_5
    Output := tests with input as {
        "policies": {
            "topOU": {
                "security_less_secure_apps": {"allowLessSecureApps": true}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage10_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
