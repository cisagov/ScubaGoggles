package assuredcontrols

import future.keywords
import data.utils


########################
# GWS.ASSUREDCONTROLS.1 #
########################

#
# Baseline GWS.ASSUREDCONTROLS.1.1
#--

AssuredControlsId1_1 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.1.1")

tests contains {
    "PolicyId": AssuredControlsId1_1,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.ASSUREDCONTROLS.1.2
#--

AssuredControlsId1_2 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.1.2")

GetFriendlyValueAccessManagement(Value) := "No preference" if {
    Value == "PREFERENCE_UNSPECIFIED"
} else := "Access by CJIS-authorized and IRS 1075-authorized Google staff only" if {
    Value == "CJIS_IRS_1075_GOOGLE_STAFF"
} else := "Access by U.S. Google staff only" if {
    Value == "US_GOOGLE_STAFF"
} else := "Access by EU Google staff or via EU virtual desktop" if {
    Value == "EU_GOOGLE_STAFF"
} else := Value

NonComplianceMessage1_2(Value) := concat(" ", [
    "Access management policy is set to ",
    GetFriendlyValueAccessManagement(Value)
])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(settings.access_management_user_scoping.accessManagementRegime)
}
if {
    some OU, settings in input.policies
    not settings.access_management_user_scoping.accessManagementRegime in [
        "CJIS_IRS_1075_GOOGLE_STAFF",
        "US_GOOGLE_STAFF"
    ]
}

tests contains {
    "PolicyId": AssuredControlsId1_2,
    "Prerequisites": ["policy/access_management_user_scoping.accessManagementRegime"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": "",
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_2) == 0
}
#--

########################
# GWS.ASSUREDCONTROLS.2 #
########################

#
# Baseline GWS.ASSUREDCONTROLS.2.1
#--

AssuredControlsId2_1 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.2.1")

tests contains {
    "PolicyId": AssuredControlsId2_1,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--
