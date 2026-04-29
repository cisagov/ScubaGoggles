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
    },
    "sites_exclusions": []
}

GoodSitesApi02 := {
    "policies": {
        "topOU": {
            "sites_service_status": {"serviceState": "DISABLED"}
        },
        "nextOU": {
            "sites_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    },
    "sites_exclusions": [
        {
            "ou": "nextOU",
            "group": "",
            "justification": "perfectly valid reason"
        }
    ]
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
    },
    "sites_exclusions": []
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
    },
    "sites_exclusions": []
}

test_SitesAPI_Correct_1 if {
    PolicyId := SitesId1_1
    Output := tests with input as GoodSitesApi01

    PassTestResult(PolicyId, Output)
}

test_SitesAPI_Correct_2 if {
    PolicyId := SitesId1_1
    Output := tests with input as GoodSitesApi02

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "Requirement met in all OUs and groups.",
        "<br>Note: Sites is enabled in the following locations but ScubaGoggles was configured to ",
        "allow exceptions for them:<ul><li>nextOU. <i>Justification: perfectly valid reason</i></li></ul>"
    ])
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
