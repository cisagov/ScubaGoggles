package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.9.1v0.2
#--
test_HighlyPriv_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.9.1v0.2"
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
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--

#
# GWS.COMMONCONTROLS.9.2v0.2
#--
test_Sensitive_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.9.2v0.2"
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
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--