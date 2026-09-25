package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi15 := {
    "policies": {
        "topOU": {
            "data_regions_data_at_rest_region": {"region": "US"},
            "data_regions_data_processing_region": {
                "limitToStorageRegion": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi15 := {
    "policies": {
        "topOU": {
            "data_regions_data_at_rest_region": {"region": "EUROPE"},
            "data_regions_data_processing_region": {
                "limitToStorageRegion": false
            }
        },
        "nextOU": {
            "data_regions_data_at_rest_region": {"region": "ANY_REGION"},
            "data_regions_data_processing_region": {
                "limitToStorageRegion": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi15a := {
    "policies": {
        "topOU": {
            "data_regions_data_at_rest_region": {"region": "REGION_UNSPECIFIED"},
            "data_regions_data_processing_region": {
                "limitToStorageRegion": true
            }
        },
        "nextOU": {
            "data_regions_data_at_rest_region": {"region": "US"},
            "data_regions_data_processing_region": {
                "limitToStorageRegion": false
            }
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_DataAtRestRegion_Correct_1 if {
    PolicyId := CommonControlsId15_1
    Output := tests with input as GoodCaseInputApi15

    PassTestResult(PolicyId, Output)
}

test_DataAtRestRegion_Incorrect_1 if {
    PolicyId := CommonControlsId15_1
    Output := tests with input as BadCaseInputApi15

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage15_1("unrestricted (any region)")},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage15_1("Europe only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DataAtRestRegion_Incorrect_2 if {
    PolicyId := CommonControlsId15_1
    Output := tests with input as BadCaseInputApi15a

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage15_1("unspecified")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DataProcessRegion_Correct_1 if {
    PolicyId := CommonControlsId15_2
    Output := tests with input as GoodCaseInputApi15

    PassTestResult(PolicyId, Output)
}

test_DataProcessRegion_Incorrect_1 if {
    PolicyId := CommonControlsId15_2
    Output := tests with input as BadCaseInputApi15

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage15_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DataProcessRegion_Incorrect_2 if {
    PolicyId := CommonControlsId15_2
    Output := tests with input as BadCaseInputApi15a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage15_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
