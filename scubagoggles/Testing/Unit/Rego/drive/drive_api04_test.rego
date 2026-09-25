package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodDriveApi04 := {
    "policies": {
        "topOU": {
            "drive_and_docs_drive_sdk": {"enableDriveSdkApiAccess": false},
            "drive_and_docs_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi04 := {
    "policies": {
        "topOU": {
            "drive_and_docs_drive_sdk": {"enableDriveSdkApiAccess": true},
            "drive_and_docs_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "drive_and_docs_drive_sdk": {"enableDriveSdkApiAccess": false}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi04a := {
    "policies": {
        "topOU": {
            "drive_and_docs_drive_sdk": {"enableDriveSdkApiAccess": false},
            "drive_and_docs_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "drive_and_docs_drive_sdk": {"enableDriveSdkApiAccess": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_SecurityUpdate_Correct_1 if {
    PolicyId := DriveId4_1
    Output := tests with input as GoodDriveApi04

    PassTestResult(PolicyId, Output)
}

test_SecurityUpdate_Incorrect_1 if {
    PolicyId := DriveId4_1
    Output := tests with input as BadDriveApi04

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage4_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SecurityUpdate_Incorrect_2 if {
    PolicyId := DriveId4_1
    Output := tests with input as BadDriveApi04a

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage4_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
