package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.6.1
# Implementation reference: https://github.com/cisagov/ScubaGoggles/issues/589
# - API/state-based check using inbound_sso_assignments (Cloud Identity API).
# - Evaluates effective inherited assignment from OU ancestry.
#--

OrgUnits := {
    "organizationUnits": [
        {
            "name": "Top OU",
            "orgUnitPath": "/",
            "orgUnitId": "id:top",
            "parentOrgUnitPath": "/"
        },
        {
            "name": "Parent",
            "orgUnitPath": "/Parent",
            "orgUnitId": "id:parent",
            "parentOrgUnitPath": "/"
        },
        {
            "name": "Child",
            "orgUnitPath": "/Parent/Child",
            "orgUnitId": "id:child",
            "parentOrgUnitPath": "/Parent"
        },
        {
            "name": "Sibling",
            "orgUnitPath": "/Sibling",
            "orgUnitId": "id:sibling",
            "parentOrgUnitPath": "/"
        }
    ]
}

BaseInput := {
    "organizational_units": OrgUnits,
    "tenant_info": {"topLevelOU": "Top OU"},
    "privileged_users_error": null,
    "inbound_sso_assignments_error": null
}

test_NoPrivilegedUsers_Compliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [],
        "inbound_sso_assignments": []
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 0
}

test_PrivilegedUser_ExplicitSsoOff_Compliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{"primaryEmail": "admin@example.org", "orgUnitPath": "Parent", "groupKeys": []}],
        "inbound_sso_assignments": [
            {"targetOrgUnit": "orgUnits/parent", "ssoMode": "SSO_OFF"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
}

test_PrivilegedUser_ExplicitSsoOn_NonCompliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{"primaryEmail": "admin@example.org", "orgUnitPath": "Parent", "groupKeys": []}],
        "inbound_sso_assignments": [
            {"targetOrgUnit": "orgUnits/parent", "ssoMode": "SAML_SSO"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    count(RuleOutput[0].ActualValue.NonCompliantOUs) == 1
}

test_PrivilegedUser_InheritsParentSsoOn_NonCompliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{"primaryEmail": "admin@example.org", "orgUnitPath": "Parent/Child", "groupKeys": []}],
        "inbound_sso_assignments": [
            {"targetOrgUnit": "orgUnits/parent", "ssoMode": "SAML_SSO"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    SomeOU := RuleOutput[0].ActualValue.NonCompliantOUs[_]
    SomeOU.Name == "Parent/Child"
}

test_PrivilegedUser_ChildOverrideToOff_Compliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{"primaryEmail": "admin@example.org", "orgUnitPath": "Parent/Child", "groupKeys": []}],
        "inbound_sso_assignments": [
            {"targetOrgUnit": "orgUnits/parent", "ssoMode": "SAML_SSO"},
            {"targetOrgUnit": "orgUnits/child", "ssoMode": "SSO_OFF"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
}

test_PrivilegedUser_TopLevelPath_InheritsRoot_NonCompliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{"primaryEmail": "admin@example.org", "orgUnitPath": "", "groupKeys": []}],
        "inbound_sso_assignments": [
            {"targetOrgUnit": "orgUnits/top", "ssoMode": "OIDC_SSO"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
}

test_PrivilegedUsers_FetchError_NoSuchEvent_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [],
        "privileged_users_error": "Permission denied",
        "inbound_sso_assignments": []
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
}

test_SsoAssignments_FetchError_NoSuchEvent_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{"primaryEmail": "admin@example.org", "orgUnitPath": "Parent", "groupKeys": []}],
        "inbound_sso_assignments": [],
        "inbound_sso_assignments_error": "insufficient scope"
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
}

test_PrivilegedUser_GroupTargetSsoOn_NonCompliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": "Parent",
            "groupKeys": ["security-admins@example.org"]
        }],
        "inbound_sso_assignments": [
            {"targetGroup": "groups/security-admins@example.org", "ssoMode": "SAML_SSO"},
            {"targetOrgUnit": "orgUnits/parent", "ssoMode": "SSO_OFF"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
}

test_PrivilegedUser_GroupTargetSsoOff_OverridesOuOn_Compliant_V1 if {
    PolicyId := CommonControlsId6_1
    Output := tests with input as object.union(BaseInput, {
        "privileged_users": [{
            "primaryEmail": "admin@example.org",
            "orgUnitPath": "Parent",
            "groupKeys": ["security-admins@example.org"]
        }],
        "inbound_sso_assignments": [
            {"targetGroup": "groups/security-admins@example.org", "ssoMode": "SSO_OFF"},
            {"targetOrgUnit": "orgUnits/parent", "ssoMode": "SAML_SSO"}
        ]
    })

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
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
