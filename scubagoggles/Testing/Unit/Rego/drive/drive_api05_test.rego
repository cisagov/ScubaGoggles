package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodDriveApi05 := {
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

BadDriveApi05 := {
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

BadDriveApi05a := {
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
    PolicyId := DriveId5_1
    Output := tests with input as GoodDriveApi05

    PassTestResult(PolicyId, Output)
}

test_DriveDesktop_Incorrect_1 if {
    PolicyId := DriveId5_1
    Output := tests with input as BadDriveApi05

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage5_1(GetFriendlyValue5_1(false, true))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DriveDesktop_Incorrect_2 if {
    PolicyId := DriveId5_1
    Output := tests with input as BadDriveApi05a

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage5_1(GetFriendlyValue5_1(false, true))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
