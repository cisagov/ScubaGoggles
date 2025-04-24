package meet

import future.keywords
import data.utils
import data.utils.GetFriendlyEnabledValue

MeetEnabled(orgunit) := utils.AppEnabled(input.policies, "meet", orgunit)

LogEvents := utils.GetEvents("meet_logs")

##############
# GWS.MEET.1 #
##############

#
# Baseline GWS.MEET.1.1
#--

MeetId1_1 := utils.PolicyIdWithSuffix("GWS.MEET.1.1")

NonComplianceMessage1_1(value) := sprintf("Who can join meetings is set to: %s",
                                          [value])

GetFriendlyValue1_1(Value) := "all users (including users not signed in with a Google account)" if {
    Value == "ALL"
} else := "users in the same organization" if {
    Value == "SAME_ORGANIZATION_ONLY"
} else := "logged in users" if {
    Value == "LOGGED_IN"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(meetAccess))
} if {
    some OU, settings in input.policies
    MeetEnabled(OU)
    meetAccess := settings.meet_safety_domain.usersAllowedToJoin
    not meetAccess in ["SAME_ORGANIZATION_ONLY", "LOGGED_IN"]
}

tests contains {
    "PolicyId": MeetId1_1,
    "Prerequisites": [
        "policy/meet_safety_domain.usersAllowedToJoin",
        "policy/meet_service_status.serviceState"
    ],
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
    "Value": "Users can receive calls from anyone"
}
if {
    some OU in utils.OUsWithEvents
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
}

NonCompliantGroups5_1 contains {
    "Name": Group,
    "Value": "Users can receive calls from anyone"
}
if {
    some Group in utils.GroupsWithEvents
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsGroup(LogEvents, SettingName, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ALL"
}

tests contains {
    "PolicyId": MeetId5_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": MeetId5_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, NonCompliantGroups5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1, "NonCompliantGroups": NonCompliantGroups5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Incoming call restrictions Allowed caller type"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs5_1) == 0, count(NonCompliantGroups5_1) == 0}
    Status := (false in Conditions) == false
}

##############
# GWS.MEET.6 #
##############

#
# Baseline GWS.MEET.6.1
#--

MeetId6_1 := utils.PolicyIdWithSuffix("GWS.MEET.6.1")

tests contains {
    "PolicyId": MeetId6_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.MEET.6.2
#--

MeetId6_2 := utils.PolicyIdWithSuffix("GWS.MEET.6.2")

tests contains {
    "PolicyId": MeetId6_2,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--
