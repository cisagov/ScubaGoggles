package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodDriveApi01 := {
    "policies": {
        "topOU": {
            "drive_and_docs_external_sharing": {
                "accessCheckerSuggestions": "RECIPIENTS_ONLY",
                "allowNonGoogleInvites": false,
                "allowNonGoogleInvitesInAllowlistedDomains": false,
                "allowPublishingFiles": false,
                "allowReceivingExternalFiles": false,
                "allowReceivingFilesOutsideAllowlistedDomains": true,
                "allowedPartiesForDistributingContent": "NONE",
                "externalSharingMode": "DISALLOWED",
                "warnForExternalSharing": true,
                "warnForSharingOutsideAllowlistedDomains": true
            },
            "drive_and_docs_general_access_default": {
                "defaultFileAccess": "PRIVATE_TO_OWNER"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
         "nextOU": {
            "drive_and_docs_external_sharing": {
                "allowNonGoogleInvites": true,
                "allowReceivingExternalFiles": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi01 := {
    "policies": {
        "topOU": {
            "drive_and_docs_external_sharing": {
                "accessCheckerSuggestions": "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC",
                "allowNonGoogleInvites": true,
                "allowNonGoogleInvitesInAllowlistedDomains": false,
                "allowPublishingFiles": true,
                "allowReceivingExternalFiles": false,
                "allowReceivingFilesOutsideAllowlistedDomains": true,
                "allowedPartiesForDistributingContent": "ALL_ELIGIBLE_USERS",
                "externalSharingMode": "ALLOWED",
                "warnForExternalSharing": false,
                "warnForSharingOutsideAllowlistedDomains": true
            },
            "drive_and_docs_general_access_default": {
                "defaultFileAccess": "PRIMARY_AUDIENCE_WITH_LINK"
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
         "nextOU": {
            "drive_and_docs_external_sharing": {
                "externalSharingMode": "ALLOWLISTED_DOMAINS",
                "warnForSharingOutsideAllowlistedDomains": false,
                "allowNonGoogleInvitesInAllowlistedDomains": true
            }
        },
         "thirdOU": {
            "drive_and_docs_external_sharing": {
                "warnForExternalSharing": true
            }
        },
         "fourthOU": {"empty intentional?": "yes"}
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadDriveApi01a := {
    "policies": {
        "topOU": {
            "drive_and_docs_external_sharing": {
                "accessCheckerSuggestions": "RECIPIENTS_ONLY",
                "allowNonGoogleInvites": false,
                "allowNonGoogleInvitesInAllowlistedDomains": false,
                "allowPublishingFiles": false,
                "allowReceivingExternalFiles": false,
                "allowReceivingFilesOutsideAllowlistedDomains": true,
                "allowedPartiesForDistributingContent": "NONE",
                "externalSharingMode": "DISALLOWED",
                "warnForExternalSharing": false,
                "warnForSharingOutsideAllowlistedDomains": true
            },
                "drive_and_docs_service_status": {"serviceState": "ENABLED"
            }
        },
         "nextOU": {
            "drive_and_docs_external_sharing": {
                "accessCheckerSuggestions": "RECIPIENTS_OR_AUDIENCE",
                "allowNonGoogleInvites": true,
                "allowNonGoogleInvitesInAllowlistedDomains": true,
                "allowPublishingFiles": true,
                "allowReceivingExternalFiles": false,
                "allowReceivingFilesOutsideAllowlistedDomains": true,
                "allowedPartiesForDistributingContent": "ELIGIBLE_INTERNAL_USERS",
                "externalSharingMode": "ALLOWLISTED_DOMAINS",
                "warnForExternalSharing": false,
                "warnForSharingOutsideAllowlistedDomains": true
                },
            "drive_and_docs_general_access_default": {
                "defaultFileAccess": "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH"
            },
        },
        "thirdOU": {
            "drive_and_docs_external_sharing": {
                "allowReceivingExternalFiles": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ExtSharing_Correct_1 if {
    PolicyId := DriveId1_1
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_ExtSharing_Incorrect_1 if {
    PolicyId := DriveId1_1
    Output := tests with input as BadDriveApi01

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("ALLOWLISTED_DOMAINS"))},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ExtSharing_Incorrect_2 if {
    PolicyId := DriveId1_1
    Output := tests with input as BadDriveApi01a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_1(GetFriendlyValue1_1("ALLOWLISTED_DOMAINS"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ReceiveExt_Correct_1 if {
    PolicyId := DriveId1_2
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_ReceiveExt_Incorrect_1 if {
    PolicyId := DriveId1_2
    Output := tests with input as BadDriveApi01a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_2(GetSharingValue("ALLOWLISTED_DOMAINS"))},
                 {"Name": "thirdOU",
                 "Value": NonComplianceMessage1_2(GetSharingValue("DISALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UserExtSharing_Correct_1 if {
    PolicyId := DriveId1_3
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_UserExtSharing_Incorrect_1 if {
    PolicyId := DriveId1_3
    Output := tests with input as BadDriveApi01

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_3(GetSharingValue("ALLOWLISTED_DOMAINS"))},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_3(GetSharingValue("ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonGoogle_Correct_1 if {
    PolicyId := DriveId1_4
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_NonGoogle_Incorrect_1 if {
    PolicyId := DriveId1_4
    Output := tests with input as BadDriveApi01

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_4(GetSharingValue("ALLOWLISTED_DOMAINS"))},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_4(GetSharingValue("ALLOWED"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NonGoogle_Incorrect_2 if {
    PolicyId := DriveId1_4
    Output := tests with input as BadDriveApi01a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_4(GetSharingValue("ALLOWLISTED_DOMAINS"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AllowPublish_Correct_1 if {
    PolicyId := DriveId1_5
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_AllowPublish_Incorrect_1 if {
    PolicyId := DriveId1_5
    Output := tests with input as BadDriveApi01

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_5},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AllowPublish_Incorrect_2 if {
    PolicyId := DriveId1_5
    Output := tests with input as BadDriveApi01a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AccessCheck_Correct_1 if {
    PolicyId := DriveId1_6
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_AccessCheck_Incorrect_1 if {
    PolicyId := DriveId1_6
    Output := tests with input as BadDriveApi01

    value := "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC"
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_6(GetFriendlyValue1_6(value))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AccessCheck_Incorrect_2 if {
    PolicyId := DriveId1_6
    Output := tests with input as BadDriveApi01a

    value := "RECIPIENTS_OR_AUDIENCE"
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_6(GetFriendlyValue1_6(value))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_MoveContent_Correct_1 if {
    PolicyId := DriveId1_7
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_MoveContent_Incorrect_1 if {
    PolicyId := DriveId1_7
    Output := tests with input as BadDriveApi01

    value := "ALL_ELIGIBLE_USERS"
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_7(GetFriendlyValue1_7(value))},
                 {"Name": "topOU",
                 "Value": NonComplianceMessage1_7(GetFriendlyValue1_7(value))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_MoveContent_Incorrect_2 if {
    PolicyId := DriveId1_7
    Output := tests with input as BadDriveApi01a

    value := "ELIGIBLE_INTERNAL_USERS"
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_7(GetFriendlyValue1_7(value))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DefaultAccess_Correct_1 if {
    PolicyId := DriveId1_8
    Output := tests with input as GoodDriveApi01

    PassTestResult(PolicyId, Output)
}

test_DefaultAccess_Incorrect_1 if {
    PolicyId := DriveId1_8
    Output := tests with input as BadDriveApi01

    value := "PRIMARY_AUDIENCE_WITH_LINK"
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_8(GetFriendlyValue1_8(value))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DefaultAccess_Incorrect_2 if {
    PolicyId := DriveId1_8
    Output := tests with input as BadDriveApi01a

    value := "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH"
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_8(GetFriendlyValue1_8(value))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
