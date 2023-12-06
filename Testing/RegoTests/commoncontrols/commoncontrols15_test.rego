package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.15.1v0.1
#--
test_Required_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "Results for GWS.COMMONCONTROLS.15 are listed in the ",
        "<a href='../IndividualReports/RulesReport.html'>Rules Report</a>."])
}
#--