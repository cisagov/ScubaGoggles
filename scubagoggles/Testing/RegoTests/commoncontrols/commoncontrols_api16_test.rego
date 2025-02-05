package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi16 := {
    "policies": {
        "topOU": {
            "early_access_apps_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi16 := {
    "policies": {
        "topOU": {
            "early_access_apps_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi16a := {
    "policies": {
        "topOU": {
            "early_access_apps_service_status": {"serviceState": "DISABLED"}
        },
        "nextOU": {
            "early_access_apps_service_status": {"serviceState": "ENABLED"}
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_EarlyAccess_Correct_1 if {
    PolicyId := CommonControlsId16_2
    Output := tests with input as GoodCaseInputApi16

    PassTestResult(PolicyId, Output)
}

test_EarlyAccess_Incorrect_1 if {
    PolicyId := CommonControlsId16_2
    Output := tests with input as BadCaseInputApi16

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage16_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EarlyAccess_Incorrect_2 if {
    PolicyId := CommonControlsId16_2
    Output := tests with input as BadCaseInputApi16a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage16_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
