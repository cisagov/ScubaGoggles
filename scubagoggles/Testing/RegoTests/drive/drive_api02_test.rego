package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodDriveApi02 := {
    "policies": {
        "topOU": {
            "drive_and_docs_shared_drive_creation": {
                "allowExternalUserAccess": false,
                "allowManagersToOverrideSettings": false,
                "allowNonMemberAccess": true,
                "allowedPartiesForDownloadPrintCopy": "EDITORS_ONLY"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
         "nextOU": {
            "drive_and_docs_external_sharing": {
                "allowNonGoogleInvites": true,
                "allowReceivingExternalFiles": false
            }
        },
        "thirdOU": {
            "security_session_controls": {
                "webSessionDuration": "700m"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi02 := {
    "policies": {
        "topOU": {
            "drive_and_docs_shared_drive_creation": {
                "allowExternalUserAccess": true,
                "allowManagersToOverrideSettings": true,
                "allowNonMemberAccess": false,
                "allowedPartiesForDownloadPrintCopy": "ALL"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi02a := {
    "policies": {
        "topOU": {
            "drive_and_docs_shared_drive_creation": {
                "allowExternalUserAccess": false,
                "allowManagersToOverrideSettings": false,
                "allowNonMemberAccess": true,
                "allowedPartiesForDownloadPrintCopy": "EDITORS_ONLY"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
         "nextOU": {
            "drive_and_docs_shared_drive_creation": {
                "allowExternalUserAccess": true,
                "allowManagersToOverrideSettings": true,
                "allowNonMemberAccess": false,
                "allowedPartiesForDownloadPrintCopy": "ALL"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ManagerOverride_Correct_1 if {
    PolicyId := DriveId2_1
    Output := tests with input as GoodDriveApi02

    PassTestResult(PolicyId, Output)
}

test_ManagerOverride_Incorrect_1 if {
    PolicyId := DriveId2_1
    Output := tests with input as BadDriveApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ManagerOverride_Incorrect_2 if {
    PolicyId := DriveId2_1
    Output := tests with input as BadDriveApi02a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage2_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExternalAccess_Correct_1 if {
    PolicyId := DriveId2_2
    Output := tests with input as GoodDriveApi02

    PassTestResult(PolicyId, Output)
}

test_ExternalAccess_Incorrect_1 if {
    PolicyId := DriveId2_2
    Output := tests with input as BadDriveApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExternalAccess_Incorrect_2 if {
    PolicyId := DriveId2_2
    Output := tests with input as BadDriveApi02a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage2_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonMemberExternalAccess_Correct_1 if {
    PolicyId := DriveId2_3
    Output := tests with input as GoodDriveApi02

    PassTestResult(PolicyId, Output)
}

test_NonMemberExternalAccess_1 if {
    PolicyId := DriveId2_3
    Output := tests with input as BadDriveApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_3}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonMemberExternalAccess_2 if {
    PolicyId := DriveId2_3
    Output := tests with input as BadDriveApi02a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage2_3}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AllowPrint_Correct_1 if {
    PolicyId := DriveId2_4
    Output := tests with input as GoodDriveApi02

    PassTestResult(PolicyId, Output)
}

test_AllowPrint_Incorrect_1 if {
    PolicyId := DriveId2_4
    Output := tests with input as BadDriveApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_4}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AllowPrint_Incorrect_2 if {
    PolicyId := DriveId2_4
    Output := tests with input as BadDriveApi02a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage2_4}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
