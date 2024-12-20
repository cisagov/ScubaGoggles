package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi11 := {
    "policies": {
        "topOU": {
            "workspace_marketplace_apps_access_options": {
                "accessLevel": "ALLOW_LISTED_APPS",
                "allowAllInternalApps": false}
        },
        "nextOU": {
            "workspace_marketplace_apps_access_options": {
                "accessLevel": "ALLOW_NONE",
                "allowAllInternalApps": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi11 := {
    "policies": {
        "topOU": {
            "workspace_marketplace_apps_access_options": {
                "accessLevel": "ALLOW_ALL",
                "allowAllInternalApps": true}
        },
        "nextOU": {
            "workspace_marketplace_apps_access_options": {
                "accessLevel": "ALLOW_LISTED_APPS",
                "allowAllInternalApps": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MarketplaceApps_Correct_1 if {
    PolicyId := CommonControlsId11_1
    Output := tests with input as GoodCaseInputApi11

    PassTestResult(PolicyId, Output)
}

test_MarketplaceApps_Incorrect_1 if {
    PolicyId := CommonControlsId11_1
    Output := tests with input as BadCaseInputApi11

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage11_1(false)},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage11_1(true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
