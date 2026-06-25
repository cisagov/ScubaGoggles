package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi07 := {
    "policies": {
        "topOU": {
            "provisioning_conflicting_accounts_management": {
                "conflictingAccountsManagement": "REPLACE_CONFLICTING_ACCOUNTS"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi07 := {
    "policies": {
        "topOU": {
            "provisioning_conflicting_accounts_management": {
                "conflictingAccountsManagement": "INVITE_CONFLICTING_ACCOUNTS"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi07a := {
    "policies": {
        "topOU": {
            "provisioning_conflicting_accounts_management": {
                "conflictingAccountsManagement": "REPLACE_CONFLICTING_ACCOUNTS"}
        },
        "nextOU": {
            "provisioning_conflicting_accounts_management": {
                "conflictingAccountsManagement": "INVITE_CONFLICTING_ACCOUNTS"}
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ConflictingAccounts_Correct_1 if {
    PolicyId := CommonControlsId7_1
    Output := tests with input as GoodCaseInputApi07

    PassTestResult(PolicyId, Output)
}

test_ConflictingAccounts_Incorrect_1 if {
    PolicyId := CommonControlsId7_1
    Output := tests with input as BadCaseInputApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ConflictingAccounts_Incorrect_2 if {
    PolicyId := CommonControlsId7_1
    Output := tests with input as BadCaseInputApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
