package sites

import future.keywords
import data.utils

###############
# GWS.SITES.1 #
###############

#
# Baseline GWS.SITES.1.1
#--

SitesId1_1 := utils.PolicyIdWithSuffix("GWS.SITES.1.1")

SitesEnabled contains OU if {
    some OU, settings in input.policies
    utils.AppExplicitStatus(input.policies, "sites", OU) == "ENABLED"
}

SitesExclusions contains OU if {
    some OU in SitesEnabled
    utils.ExceptionConfigured(OU, "sites_exclusions")
}

SitesExclusionsFormatted contains Message if {
    some OU in SitesExclusions
    Justification := utils.ExceptionJustification(OU, "sites_exclusions")
    Message := sprintf("<li>%s. %s</li>", [OU, utils.FormatJustification(Justification)])
}

NonComplianceMessage1_1 := "Service status for Sites is enabled"

NonCompliantOUs1_1  contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1
}
if {
    some OU, settings in input.policies
    OU in (SitesEnabled - SitesExclusions)
}

SitesExceptionMessage := "" if {
    count(SitesExclusions) == 0
} else := Message if {
    Message := concat("", [
        "<br>Note: Sites is enabled in the following locations but ScubaGoggles was configured to ",
        "allow exceptions for them:<ul>",
        concat("", SitesExclusionsFormatted),
        "</ul>"
    ])
}

tests contains {
    "PolicyId": SitesId1_1,
    "Prerequisites": ["policy/sites_service_status.serviceState"],
    "Criticality": "Should",
    "ReportDetails": concat("", [utils.ReportDetails(NonCompliantOUs1_1, []), SitesExceptionMessage]),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}
#--
