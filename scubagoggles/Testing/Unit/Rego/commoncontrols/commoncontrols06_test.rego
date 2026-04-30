package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.6.1
# Implementation reference: https://github.com/cisagov/ScubaGoggles/issues/589
# - Determines OUs containing highly privileged accounts.
# - Verifies the most recent "Inbound SSO Settings SSO mode" event for each
#   such OU is "SSO off" or DELETE_APPLICATION_SETTING (i.e. SSO is disabled,
#   so admin accounts authenticate against Google Workspace).
#--

# Helper for building an "Inbound SSO Settings SSO mode" change event for a
# given OU/value at the given timestamp.
SsoModeEvent(OrgUnit, NewValue, Time) := {
    "id": {"time": Time},
    "events": [{
        "parameters": [
            {"name": "ORG_UNIT_NAME", "value": OrgUnit},
            {"name": "SETTING_NAME", "value": "Inbound SSO Settings SSO mode"},
            {"name": "NEW_VALUE", "value": NewValue},
            {"name": "APPLICATION_NAME", "value": "Security"}
        ]
    }]
}

# Helper for building a DELETE_APPLICATION_SETTING event for the
# "Inbound SSO Settings SSO mode" setting.  These events have no NEW_VALUE
# and the synthetic NewValue defaults to "DELETE_APPLICATION_SETTING".
SsoModeDeleteEvent(OrgUnit, Time) := {
    "id": {"time": Time},
    "events": [{
        "name": "DELETE_APPLICATION_SETTING",
        "parameters": [
            {"name": "ORG_UNIT_NAME", "value": OrgUnit},
            {"name": "SETTING_NAME", "value": "Inbound SSO Settings SSO mode"},
            {"name": "APPLICATION_NAME", "value": "Security"}
        ]
    }]
}

test_NoPrivilegedUsers_Compliant_V1 if {
    # No privileged users at all -> vacuously compliant.
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": []},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 0
}

test_PrivilegedUser_SsoOff_Compliant_V1 if {
    # Privileged user in an OU whose most recent SSO event is "SSO off".
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": "Admins"
        }],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": [
            SsoModeEvent("Admins", "SSO off", "2024-01-01T00:00:00Z")
        ]},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 0
}

test_PrivilegedUser_SsoDeleted_Compliant_V1 if {
    # Privileged user in an OU whose most recent SSO event is a deletion of
    # the SSO setting. This is also treated as SSO disabled (default).
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": "Admins"
        }],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": [
            SsoModeEvent("Admins", "OnTopOfDomainAuthentication", "2024-01-01T00:00:00Z"),
            SsoModeDeleteEvent("Admins", "2024-06-01T00:00:00Z")
        ]},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 0
}

test_PrivilegedUser_NoSsoEvents_Compliant_V1 if {
    # Privileged user in an OU but no SSO mode events for that OU.
    # Per the inheritance default the OU is treated as compliant.
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": "Admins"
        }],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": []},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 0
}

test_PrivilegedUser_SsoOn_NonCompliant_V1 if {
    # Privileged user in an OU whose most recent SSO event enables SSO.
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": "Admins"
        }],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": [
            SsoModeEvent("Admins", "SSO off", "2024-01-01T00:00:00Z"),
            SsoModeEvent("Admins", "OnTopOfDomainAuthentication", "2024-06-01T00:00:00Z")
        ]},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 1
    SomeOU := RuleOutput[0].ActualValue.NonCompliantOUs[_]
    SomeOU.Name == "Admins"
}

test_PrivilegedUser_MultipleOUs_PartiallyNonCompliant_V1 if {
    # Two privileged user OUs, one compliant, one not.
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [
            {"primaryEmail": "ok@example.org",  "orgUnitPath": "OkOU"},
            {"primaryEmail": "bad@example.org", "orgUnitPath": "BadOU"}
        ],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": [
            SsoModeEvent("OkOU",  "SSO off",                       "2024-06-01T00:00:00Z"),
            SsoModeEvent("BadOU", "OnTopOfDomainAuthentication",   "2024-06-01T00:00:00Z")
        ]},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    Names := {ou.Name | some ou in RuleOutput[0].ActualValue.NonCompliantOUs}
    Names == {"BadOU"}
}

test_PrivilegedUser_TopLevelOU_NonCompliant_V1 if {
    # Privileged user with empty orgUnitPath should map to the top-level OU.
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": ""
        }],
        "privileged_users_error": null,
        "commoncontrols_logs": {"items": [
            SsoModeEvent("Test Top-Level OU", "OnTopOfDomainAuthentication",
                         "2024-06-01T00:00:00Z")
        ]},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 1
}

test_PrivilegedUsers_FetchError_NoSuchEvent_V1 if {
    # If the provider failed to retrieve privileged users, the policy is
    # marked NoSuchEvent (manual review required) rather than silently
    # passing.
    PolicyId := CommonControlsId6_1
    Output := tests with input as {
        "privileged_users": [],
        "privileged_users_error": "Permission denied",
        "commoncontrols_logs": {"items": []},
        "tenant_info": {"topLevelOU": "Test Top-Level OU"}
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
}
#--

#
# GWS.COMMONCONTROLS.6.2
#--
test_Count_Correct_V1 if {
    # 2 super admins
    PolicyId := CommonControlsId6_2
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
        "<i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Correct_V2 if {
    # 3 super admins
    PolicyId := CommonControlsId6_2
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
        "<i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Correct_V3 if {
    # 8 super admins
    PolicyId := CommonControlsId6_2
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
            },
            {
                "primaryEmail": "admin6@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin7@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin8@example.org",
                "orgUnitPath": ""
            },
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following super admins are configured: ",
        "admin1@example.org, admin2@example.org, admin3@example.org, admin4@example.org, ",
        "admin5@example.org, admin6@example.org, admin7@example.org, admin8@example.org.",
        " <i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Incorrect_V1 if {
    # 9 super admins
    PolicyId := CommonControlsId6_2
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
            },
            {
                "primaryEmail": "admin6@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin7@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin8@example.org",
                "orgUnitPath": ""
            },
            {
                "primaryEmail": "admin9@example.org",
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
        "admin1@example.org, admin2@example.org, admin3@example.org, admin4@example.org, admin5@example.org, ",
        "admin6@example.org, admin7@example.org, admin8@example.org, admin9@example.org.",
        " <i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}

test_Count_Incorrect_V2 if {
    # 1 super admins
    PolicyId := CommonControlsId6_2
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
        "admin1@example.org. <i>Note: Exceptions are allowed for \"break glass\" super admin accounts. ",
        "\"Break glass\" accounts can be specified in a config file. ",
        "0 break glass accounts are currently configured.<i>"
    ])
}
#--
