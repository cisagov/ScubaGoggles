package chat
import future.keywords

#
# GWS.CHAT.5.1v0.3
#--

test_FromList_Correct_V1 if {
    # Test enforcing MFA when there's only one event set to only key
    PolicyId := "GWS.CHAT.5.1v0.3"
    Output := tests with input as {
        "chat_logs": {"items": [
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