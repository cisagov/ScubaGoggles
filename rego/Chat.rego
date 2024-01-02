package chat
import future.keywords
import data.utils.TopLevelOU
import data.utils.FilterEvents
import data.utils.GetLastEvent
import data.utils.OUsWithEvents
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

##############
# GWS.CHAT.1 #
##############

#
# Baseline GWS.CHAT.1v1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents("ChatArchivingProto chatsDefaultToOffTheRecord", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "ChatArchivingProto chatsDefaultToOffTheRecord", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "ChatArchivingProto chatsDefaultToOffTheRecord", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CHAT.1.2v0.1
#--
NonCompliantOUs1_2 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents( "ChatArchivingProto allow_chat_archiving_setting_modification", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "ChatArchivingProto allow_chat_archiving_setting_modification", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "ChatArchivingProto allow_chat_archiving_setting_modification", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--


##############
# GWS.CHAT.2 #
##############

#
# Baseline GWS.CHAT.2.2v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents( "DynamiteFileSharingSettingsProto external_file_sharing_setting", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "NO_FILES"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CHAT.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "DynamiteFileSharingSettingsProto external_file_sharing_setting", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "DynamiteFileSharingSettingsProto external_file_sharing_setting", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

##############
# GWS.CHAT.3 #
##############

#
# Baseline GWS.CHAT.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents( "RoomOtrSettingsProto otr_state", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    not contains("DEFAULT_ON_THE_RECORD ALWAYS_ON_THE_RECORD", LastEvent.NewValue)
}

tests contains {
    "PolicyId": "GWS.CHAT.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "RoomOtrSettingsProto otr_state", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "RoomOtrSettingsProto otr_state", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

##############
# GWS.CHAT.4 #
##############

#
# Baseline GWS.CHAT.4.1v0.1
#--
NonCompliantOUs4_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents( "RestrictChatProto restrictChatToOrganization", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "RestrictChatProto restrictChatToOrganization", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "RestrictChatProto restrictChatToOrganization", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--

#
# Baseline GWS.CHAT.4.2v0.1
#--
NonCompliantOUs4_2 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents( "RestrictChatProto externalChatRestriction", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "NO_RESTRICTION"
}

tests contains {
    "PolicyId": "GWS.CHAT.4.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "RestrictChatProto externalChatRestriction", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.4.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "RestrictChatProto externalChatRestriction", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_2) == 0
}
#--

##############
# GWS.CHAT.5 #
##############

#
# GWS.CHAT.5.1v0.1
#--
NonCompliantOUs5_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents( "Chat app Settings - Chat apps enabled", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents( "Chat app Settings - Chat apps enabled", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents( "Chat app Settings - Chat apps enabled", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--

tests contains {
    "PolicyId": "GWS.CHAT.6.1v0.1",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--