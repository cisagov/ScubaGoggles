package sites

import future.keywords
import data.utils

SitesEnabled(orgunit) if utils.AppExplicitStatus(input.policies,
                                                 "sites",
                                                 orgunit) == "ENABLED"

###############
# GWS.SITES.1 #
###############

#
# Baseline GWS.SITES.1.1
#--

SitesId1_1 := utils.PolicyIdWithSuffix("GWS.SITES.1.1")

NonComplianceMessage1_1 := "Service status for Sites is enabled"

NonCompliantOUs1_1  contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1
}
if {
    some OU, settings in input.policies
    SitesEnabled(OU)
}

tests contains {
    "PolicyId": SitesId1_1,
    "Prerequisites": ["policy/sites_service_status.serviceState"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}
#--
