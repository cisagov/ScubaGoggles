package gemini

import future.keywords
import data.utils

#
# Baseline GWS.GEMINI.1.1
#--

GeminiId1_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.1.1")

NonComplianceMessage1_1 := "Gemini access regardless of license is enabled."

GeminiEnabled(orgunit) := utils.AppEnabled(input.policies, "gemini_app", orgunit)

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1
} if {
    some OU, settings in input.policies
    GeminiEnabled(OU)
    settings.gemini_app_unlicensed_user_access.enabled == true
}

tests contains {
    "PolicyId": GeminiId1_1,
    "Prerequisites": [
        "policy/gemini_app_unlicensed_user_access.enabled",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.GEMINI.2.1
#--

GeminiId2_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.2.1")

NonComplianceMessage2_1 := "Gemini Beta features are enabled."

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1
} if {
    some OU, settings in input.policies
    settings.gemini_for_workspace_beta_features.enabled == true
}

tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "policy/gemini_for_workspace_beta_features.enabled"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_1) == 0
}
#--

##############
# GWS.GEMINI.3 #
##############

#
# Baseline GWS.GEMINI.3.1
#--

GeminiId3_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.3.1")

tests contains {
    "PolicyId": GeminiId3_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.GEMINI.3.2
#--

GeminiId3_2 := utils.PolicyIdWithSuffix("GWS.GEMINI.3.2")

tests contains {
    "PolicyId": GeminiId3_2,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##############
# GWS.GEMINI.4 #
##############

#
# Baseline GWS.GEMINI.4.1
#--

GeminiId4_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.4.1")

tests contains {
    "PolicyId": GeminiId4_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--
