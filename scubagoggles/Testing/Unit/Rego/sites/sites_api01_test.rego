package sites

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodSitesApi01 := {
    "policies": {
        "topOU": {
            "sites_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadSitesApi01 := {
    "policies": {
        "topOU": {
            "sites_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "sites_service_status": {"serviceState": "ENABLED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadSitesApi01a := {
    "policies": {
        "topOU": {
            "sites_service_status": {"serviceState": "DISABLED"}
        },
        "topOU (group \"Even More Secret Group\")": {
            "sites_service_status": {"serviceState": "ENABLED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_SitesAPI_Correct_1 if {
    PolicyId := SitesId1_1
    Output := tests with input as GoodSitesApi01

    PassTestResult(PolicyId, Output)
}

test_SitesAPI_Incorrect_1 if {
    PolicyId := SitesId1_1
    Output := tests with input as BadSitesApi01

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_1},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SitesAPI_Incorrect_2 if {
    PolicyId := SitesId1_1
    Output := tests with input as BadSitesApi01a

    failedOU := [{"Name": "topOU (group \"Even More Secret Group\")",
                 "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
