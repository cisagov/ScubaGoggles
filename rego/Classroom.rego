package classroom

import data.utils
import future.keywords

###################
# GWS.CLASSROOM.1 #
###################

#
# Baseline GWS.CLASSROOM.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
   some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("ClassMembershipSettingsGroup who_can_join_classes", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("ClassMembershipSettingsGroup who_can_join_classes", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {

    Events := utils.FilterEvents("ClassMembershipSettingsGroup who_can_join_classes", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CLASSROOM.1.2v0.1
#--
NonCompliantOUs1_2 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("ClassMembershipSettingsGroup which_classes_can_users_join", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("ClassMembershipSettingsGroup which_classes_can_users_join", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("ClassMembershipSettingsGroup which_classes_can_users_join", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--

###################
# GWS.CLASSROOM.2 #
###################

#
# Baseline GWS.CLASSROOM.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("ApiDataAccessSettingProto api_access_enabled", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents("ApiDataAccessSettingProto api_access_enabled", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("ApiDataAccessSettingProto api_access_enabled", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

###################
# GWS.CLASSROOM.3 #
###################

#
# Baseline GWS.CLASSROOM.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("RosterImportSettingsProto sis_integrator", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "SIS_INTEGRATOR_NONE"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEvents("RosterImportSettingsProto sis_integrator", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("RosterImportSettingsProto sis_integrator", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

###################
# GWS.CLASSROOM.4 #
###################

#
# Baseline GWS.CLASSROOM.4.1v0.1
#--
NonCompliantOUs4_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents("StudentUnenrollmentSettingsProto who_can_unenroll_students", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEvents("StudentUnenrollmentSettingsProto who_can_unenroll_students", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents("StudentUnenrollmentSettingsProto who_can_unenroll_students", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--
