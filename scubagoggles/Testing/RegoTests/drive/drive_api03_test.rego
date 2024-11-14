package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodDriveApi03 := {
    "policies": {
        "topOU": {
            "drive_and_docs_file_security_update": {
                "allowUsersToManageUpdate": false,
                "securityUpdate": "APPLY_TO_IMPACTED_FILES"
            },
            "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi03 := {
    "policies": {
        "topOU": {
            "drive_and_docs_file_security_update": {
                "allowUsersToManageUpdate": true,
                "securityUpdate": "APPLY_TO_IMPACTED_FILES"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
        "nextOU": {
            "drive_and_docs_file_security_update": {
                "allowUsersToManageUpdate": false,
                "securityUpdate": "REMOVE_FROM_IMPACTED_FILES"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi03a := {
    "policies": {
        "topOU": {
            "drive_and_docs_file_security_update": {
                "allowUsersToManageUpdate": false,
                "securityUpdate": "REMOVE_FROM_IMPACTED_FILES"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
        "nextOU": {
            "drive_and_docs_file_security_update": {
                "allowUsersToManageUpdate": true,
                "securityUpdate": "APPLY_TO_IMPACTED_FILES"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_SecurityUpdate_Correct_1 if {
    PolicyId := DriveId3_1
    Output := tests with input as GoodDriveApi03

    PassTestResult(PolicyId, Output)
}

test_SecurityUpdate_Incorrect_1 if {
    PolicyId := DriveId3_1
    Output := tests with input as BadDriveApi03

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage3_1("REMOVE_FROM_IMPACTED_FILES",
                                                   false)},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage3_1("", true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SecurityUpdate_Incorrect_2 if {
    PolicyId := DriveId3_1
    Output := tests with input as BadDriveApi03a

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage3_1("", true)},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage3_1("REMOVE_FROM_IMPACTED_FILES",
                                                   false)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
