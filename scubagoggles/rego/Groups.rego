package groups

import future.keywords
import data.utils

GroupsEnabled(orgunit) := utils.AppEnabled(input.policies, "groups_for_business", orgunit)

GetFriendlyYesNoBoolean(Value) := "Yes" if {
    Value == true
} else := "No" if {
    Value == false
} else := Value

################
# GWS.GROUPS.1 #
################

#
# Baseline GWS.GROUPS.1.1
#--

GroupsId1_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.1.1")

GetFriendlyValue1_1(Value) := "Users in your domain only" if {
    Value == "DOMAIN_USERS_ONLY"
} else := "Any user" if {
    Value == "ANYONE_CAN_ACCESS"
} else := Value

NonComplianceMessage1_1(value) := sprintf("Group access set to: %s", [value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(whoCanShare))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    whoCanShare := settings.groups_for_business_groups_sharing.collaborationCapability
    whoCanShare != "DOMAIN_USERS_ONLY"
}

tests contains {
    "PolicyId": GroupsId1_1,
    "Prerequisites": [
        "policy/groups_for_business_service_status.serviceState",
        "policy/groups_for_business_groups_sharing.collaborationCapability"
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
# Baseline GWS.GROUPS.1.2
#--

GroupsId1_2 := utils.PolicyIdWithSuffix("GWS.GROUPS.1.2")

NonComplianceMessage1_2(value) := sprintf("Allowing external group members is set to: %s", [value])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetFriendlyYesNoBoolean(allowExternal))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    allowExternal := settings.groups_for_business_groups_sharing.ownersCanAllowExternalMembers
    allowExternal != false
}

tests contains {
    "PolicyId": GroupsId1_2,
    "Prerequisites": [
        "policy/groups_for_business_service_status.serviceState",
        "policy/groups_for_business_groups_sharing.ownersCanAllowExternalMembers"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs":NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_2) == 0
}
#--

#
# Baseline GWS.GROUPS.1.3
#--

GroupsId1_3 := utils.PolicyIdWithSuffix("GWS.GROUPS.1.3")

NonComplianceMessage1_3(value) := sprintf("Allowing external email is set to: %s", [value])

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_3(GetFriendlyYesNoBoolean(allowExternal))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    allowExternal := settings.groups_for_business_groups_sharing.ownersCanAllowIncomingMailFromPublic
    allowExternal != false
}

tests contains {
    "PolicyId": GroupsId1_3,
    "Prerequisites": [
        "policy/groups_for_business_service_status.serviceState",
        "policy/groups_for_business_groups_sharing.ownersCanAllowIncomingMailFromPublic"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_3) == 0
}
#--

################
# GWS.GROUPS.2 #
################

#
# Baseline GWS.GROUPS.2.1
#--

GroupsId2_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.2.1")

GetFriendlyValue2_1(Value) := "Administrators only" if {
    Value == "ADMIN_ONLY"
} else := "Users in your domain only" if {
    Value == "USERS_IN_DOMAIN"
} else := "Any user" if {
    Value == "ANYONE_CAN_CREATE"
} else := Value

NonComplianceMessage2_1(value) := sprintf("Groups can be created by: %s", [value])

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(whoCreates))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    whoCreates := settings.groups_for_business_groups_sharing.createGroupsAccessLevel
    whoCreates != "ADMIN_ONLY"
}

tests contains {
    "PolicyId": GroupsId2_1,
    "Prerequisites": [
        "policy/groups_for_business_service_status.serviceState",
        "policy/groups_for_business_groups_sharing.createGroupsAccessLevel"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.GROUPS.3 #
################

#
# Baseline GWS.GROUPS.3.1
#--

GroupsId3_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.3.1")

GetFriendlyValue3_1(Value) := "Owners" if {
    Value == "OWNERS"
} else := "Managers" if {
    Value == "MANAGERS"
} else := "Group members only" if {
    Value == "GROUP_MEMBERS"
} else := "Users in your domain only" if {
    Value == "DOMAIN_USERS"
} else := "Any user" if {
    Value == "ANYONE_CAN_VIEW_TOPICS"
} else := Value

NonComplianceMessage3_1(value) := sprintf("Group conversations can be viewed by: %s", [value])

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyValue3_1(whoCanView))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    whoCanView := settings.groups_for_business_groups_sharing.viewTopicsDefaultAccessLevel
    whoCanView != "GROUP_MEMBERS"
}

tests contains {
    "PolicyId": GroupsId3_1,
    "Prerequisites": [
        "policy/groups_for_business_service_status.serviceState",
        "policy/groups_for_business_groups_sharing.viewTopicsDefaultAccessLevel"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs3_1) == 0
}
#--

################
# GWS.GROUPS.4 #
################

#
# Baseline GWS.GROUPS.4.1
#--
GroupsId4_1 := utils.PolicyIdWithSuffix("GWS.GROUPS.4.1")

NonComplianceMessage4_1(value) := sprintf("Group may be hidden: %s", [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyYesNoBoolean(canHideGroups))
} if {
    some OU, settings in input.policies
    GroupsEnabled(OU)
    canHideGroups := settings.groups_for_business_groups_sharing.ownersCanHideGroups
    canHideGroups != false
}

tests contains {
    "PolicyId": GroupsId4_1,
    "Prerequisites": [
        "policy/groups_for_business_service_status.serviceState",
        "policy/groups_for_business_groups_sharing.ownersCanHideGroups"
    ],
    "Criticality": "Shall",
    "ReportDetails":utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs4_1) == 0
}
#--