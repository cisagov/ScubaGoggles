package sites

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

test_SitesAPI_Comply_1 if {
    PolicyId := SitesId1_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "sites_service_status": {
                    "serviceState": "DISABLED"
                },
            },
            "nextOU": {
                "sites_service_status": {
                    # Case doesn't matter
                    "serviceState": "DisaBled"
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_SitesAPI_NonComply_1 if {
    PolicyId := SitesId1_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "sites_service_status": {
                    "serviceState": "ENABLED"
                }
            },
            "nextOU": {
                "sites_service_status": {
                    # Fail even if some unexpected value (not en/disabled)
                    "serviceState": "invalid"
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_1},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SitesAPI_NonComply_2 if {
    PolicyId := SitesId1_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "sites_service_status": {
                    "serviceState": "ENABLED"
                }
            },
            "topOU (group \"Even More Secret Group\")": {
                "sites_service_status": {
                    "serviceState": "ENABLED"
                }
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1},
                 {"Name": "topOU (group \"Even More Secret Group\")",
                 "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
