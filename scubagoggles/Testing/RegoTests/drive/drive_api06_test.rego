package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodDriveApi06 := {
    "policies": {
        "topOU": {
            "drive_and_docs_drive_for_desktop": {
                "allowDriveForDesktop": false,
                "restrictToAuthorizedDevices": true
            },
            "drive_and_docs_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "drive_and_docs_drive_for_desktop": {
                "allowDriveForDesktop": true,
                "restrictToAuthorizedDevices": true
            },
        },
        "thirdOU": {
            "drive_and_docs_drive_for_desktop": {
                "restrictToAuthorizedDevices": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi06 := {
    "policies": {
        "topOU": {
            "drive_and_docs_drive_for_desktop": {
                "allowDriveForDesktop": true,
                "restrictToAuthorizedDevices": false
            },
            "drive_and_docs_service_status": {"serviceState": "ENABLED"}
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi06a := {
    "policies": {
        "topOU": {
            "drive_and_docs_drive_for_desktop": {
                "allowDriveForDesktop": false,
                "restrictToAuthorizedDevices": false
            },
            "drive_and_docs_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "drive_and_docs_drive_for_desktop": {"allowDriveForDesktop": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_DriveDesktop_Correct_1 if {
    PolicyId := DriveId6_1
    Output := tests with input as GoodDriveApi06

    PassTestResult(PolicyId, Output)
}

test_DriveDesktop_Incorrect_1 if {
    PolicyId := DriveId6_1
    Output := tests with input as BadDriveApi06

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(false, true))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DriveDesktop_Incorrect_2 if {
    PolicyId := DriveId6_1
    Output := tests with input as BadDriveApi06a

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(false, true))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
