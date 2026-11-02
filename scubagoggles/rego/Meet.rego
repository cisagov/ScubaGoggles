package meet

import future.keywords
import data.utils
import data.utils.GetFriendlyEnabledValue

MeetEnabled(orgunit) := utils.AppEnabled(input.policies, "meet", orgunit)

##############
# GWS.MEET.1 #
##############

#
# Baseline GWS.MEET.1.1
#--

MeetId1_1 := utils.PolicyIdWithSuffix("GWS.MEET.1.1")

NonComplianceMessage1_1(value) := sprintf("Who can join meetings without asking is set to: %s",
                                          [value])

GetFriendlyValue1_1(Value) := "anyone" if {
    Value == "OPEN"
} else := "users in the same organization" if {
    Value == "TRUSTED"
} else := "invited users only" if {
    Value == "RESTRICTED"
} else := "unspecified" if {
    Value == "ALLOWED_AUDIENCE_UNSPECIFIED"
 } else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(meetAccess))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    meetAccess := settings.meet_meet_joining.allowedAudience
    not meetAccess in ["TRUSTED", "RESTRICTED"]
}

tests contains {
    "PolicyId": MeetId1_1,
    "Prerequisites": [
        "policy/meet_meet_joining.allowedAudience",
        "policy/meet_service_status.serviceState"
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

##############
# GWS.MEET.2 #
##############

#
# Baseline GWS.MEET.2.1
#--

MeetId2_1 := utils.PolicyIdWithSuffix("GWS.MEET.2.1")

NonComplianceMessage2_1(value) := sprintf("What meetings can users join is set to: %s",
                                          [value])

GetFriendlyValue2_1(Value) := "any meetings (including meetings created with personal accounts)" if {
    Value == "ALL"
} else := "meetings hosted by the same organization" if {
    Value == "SAME_ORGANIZATION_ONLY"
} else := "meetings hosted by any workspace organization" if {
    Value == "ANY_WORKSPACE_ORGANIZATION"
} else := Value

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(meetAccess))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    meetAccess := settings.meet_safety_access.meetingsAllowedToJoin
    not meetAccess in ["SAME_ORGANIZATION_ONLY", "ANY_WORKSPACE_ORGANIZATION"]
}

tests contains {
    "PolicyId": MeetId2_1,
    "Prerequisites": [
        "policy/meet_safety_access.meetingsAllowedToJoin",
        "policy/meet_service_status.serviceState"
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
# GWS.MEET.3 #
##############

#
# Baseline GWS.MEET.3.1
#--

MeetId3_1 := utils.PolicyIdWithSuffix("GWS.MEET.3.1")

NonComplianceMessage3_1(value) := sprintf("Host management when video calls start is: %s",
                                          [value])

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyEnabledValue(hostMgt))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    hostMgt := settings.meet_safety_host_management.enableHostManagement
    hostMgt != true
}

tests contains {
    "PolicyId": MeetId3_1,
    "Prerequisites": [
        "policy/meet_safety_host_management.enableHostManagement",
        "policy/meet_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs3_1) == 0
}
#--

##############
# GWS.MEET.4 #
##############

#
# Baseline GWS.MEET.4.1
#--

MeetId4_1 := utils.PolicyIdWithSuffix("GWS.MEET.4.1")

NonComplianceMessage4_1(value) := sprintf("Warning label for external or unidentified meeting participants is: %s",
                                          [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyEnabledValue(extWarn))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    extWarn := settings.meet_safety_external_participants.enableExternalLabel
    extWarn != true
}

tests contains {
    "PolicyId": MeetId4_1,
    "Prerequisites": [
        "policy/meet_safety_external_participants.enableExternalLabel",
        "policy/meet_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs4_1) == 0
}
#--

##############
# GWS.MEET.5 #
##############

#
# Baseline GWS.MEET.5.1
#--

MeetId5_1 := utils.PolicyIdWithSuffix("GWS.MEET.5.1")

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": "Automatic recording is enabled."
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    AutoRecord := settings.meet_automatic_recording.enabled
    AutoRecord == true
}

tests contains {
    "PolicyId": MeetId5_1,
    "Prerequisites": [
        "policy/meet_automatic_recording.enabled",
        "policy/meet_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_1) == 0
}
#--

#
# Baseline GWS.MEET.5.2
#--

MeetId5_2 := utils.PolicyIdWithSuffix("GWS.MEET.5.2")

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": "Automatic transcription is enabled."
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    AutoRecord := settings.meet_automatic_transcription.enabled
    AutoRecord == true
}

tests contains {
    "PolicyId": MeetId5_2,
    "Prerequisites": [
        "policy/meet_automatic_transcription.enabled",
        "policy/meet_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_2) == 0
}
#--
