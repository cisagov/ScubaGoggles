package drive
import future.keywords

#
# GWS.DRIVEDOCS.7.1v0.1
#--
test_Rule_Correct_V1 if {
    # Test Attachment Compliance Filtering when there's only one event
    PolicyId := "GWS.DRIVEDOCS.7.1v0.1"
    Output := tests with input as {
        "gmail_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--