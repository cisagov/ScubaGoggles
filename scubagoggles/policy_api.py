"""Google Policy API class implementation
"""

import io
import json
import logging
import os
import re
import sys
import time

from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from random import random
from time import sleep

from google.auth.transport.requests import AuthorizedSession

from scubagoggles.auth import GwsAuth

log = logging.getLogger(__name__)

# Not all lambdas are bad, you know (see below)...
# pylint: disable=unnecessary-lambda-assignment


class PolicyAPI:

    """Implementation for accessing Google Policy API.  It should be used as
    a context manager (see 'with' statement) so the Google API resource is
    closed when it's no longer needed.
    """

    # LAMBDAS!  They're VOODOO to some, just like the "goto".  The following
    # are short functions that evaluate whether the Google API setting value
    # is exactly or roughly what's expected.  Using lambdas encapsulates the
    # functionality within the class without the bother of making them
    # static.  They're simple and do the job, and they can be placed close
    # to the policy settings where they're referenced.

    isBool = lambda x: isinstance(x, bool)

    # Google's "enum" type is essentially the string name for the enumeration
    # member.  It must be all alphanumeric characters with possible underscores.

    isEnum = lambda x: isinstance(x, str) and re.match(r'^[A-Z0-9_]+$', x)

    isInt = lambda x: isinstance(x, int)

    isListStrings = lambda x: (isinstance(x, list)
                               and all(isinstance(e, str) for e in x))

    isState = lambda x: x.lower() in ('disabled', 'enabled')

    isString = lambda x: isinstance(x, str)

    isDuration = lambda x: isinstance(x, str) and re.match(r'(?i)^\d+[hms]$', x)

    isTimestamp = lambda x: (isinstance(x, str)
                             and re.match(r'(?i)^\d{4}(?:-\d{2}){2}T\d{2}'
                                          r'(?::\d{2}){2}(?:\.\d+)?z$',
                                          x))

    # There may be duplicate policies returned for an orgunit/group and
    # section.  The policies must be "reduced" to single settings using
    # a method.  The default "reducer" method is to select the policy with the
    # highest "sort order", and this is applied if a reducer is not specified
    # in the expected policy settings below.

    _merge_reducer = '_merge'

    # This is the list of policy settings returned by Google that are relevant
    # to the secure baselines.  Settings that are not relevant are ignored
    # (i.e., they are NOT included in this data structure - these are settings
    # that are not referenced in any of our policy code). The key is the section
    # (what Google calls "setting type") (NOTE that while Google returns a
    # setting type with a period (.) delimiting the type (e.g.,
    # "sites.service_status"), we convert the periods into underscores because
    # Rego uses the period to delimit hierarchy).  The setting is a dictionary
    # containing the name of each setting and a function that will validate that
    # the setting value is correct.  Optionally, a reducer may be given if it
    # differs from the default ("maximum sort order") - this is set using the
    # "reducer" key.
    #
    # The entries are ordered alphabetically (not that they have to, but it
    # does make finding them in this data structure easier).  If you need to
    # add a new entry, it may be easiest to copy a similar entry and update
    # it with the correct section/setting names and verifier, and finally
    # whether a reducer is needed.

    _expectedPolicySettings = {
        'analytics_service_status': {'settings': {'serviceState': isState}},
        'applied_digital_skills_service_status': {'settings': {
            'serviceState': isState}},
        'appsheet_service_status': {'settings': {'serviceState': isState}},
        'blogger_service_status': {'settings': {'serviceState': isState}},
        'blogger_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'books_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'calendar_appointment_schedules': {'settings': {
            'enablePayments': isBool}},
        'calendar_external_invitations': {'settings': {'warnOnInvite': isBool}},
        'calendar_interoperability': {'settings': {
            'enableExchangeRoomBooking': isBool,
            'enableFullEventDetails': isBool,
            'enableInteroperability': isBool}},
        'calendar_primary_calendar_max_allowed_external_sharing': {'settings': {
            'maxAllowedExternalSharing': isEnum}},
        'calendar_secondary_calendar_max_allowed_external_sharing': {
            'settings': {'maxAllowedExternalSharing': isEnum}},
        'calendar_service_status': {'settings': {'serviceState': isState}},
        'chat_chat_file_sharing': {'settings': {
            'externalFileSharing': isEnum,
            'internalFileSharing': isEnum}},
        'chat_chat_history': {'reducer': _merge_reducer,
                              'settings': {
                                  'allowUserModification': isBool,
                                  'historyOnByDefault': isBool}},
        'chat_external_chat_restriction': {'reducer': _merge_reducer,
                                           'settings': {
            'allowExternalChat': isBool,
            'externalChatRestriction': isEnum}},
        'chat_service_status': {'settings': {'serviceState': isState}},
        'chat_space_history': {'settings': {'historyState': isEnum}},
        'chrome_canvas_service_status': {'settings': {'serviceState': isState}},
        'classroom_api_data_access': {'settings': {'enableApiAccess': isBool}},
        'classroom_class_membership': {'settings': {
            'whoCanJoinClasses': isEnum,
            'whichClassesCanUsersJoin': isEnum}},
        'classroom_guardian_access': {'settings': {
            'allowAccess': isBool,
            'whoCanManageGuardianAccess': isEnum}},
        'classroom_roster_import': {'settings': {'rosterImportOption': isEnum}},
        'classroom_student_unenrollment': {'settings': {
            'whoCanUnenrollStudents': isEnum}},
        'classroom_teacher_permissions': {'settings': {
            'whoCanCreateClasses': isEnum}},
        'cloud_search_service_status': {'settings': {'serviceState': isState}},
        'drive_and_docs_drive_for_desktop': {'settings': {
            'allowDriveForDesktop': isBool,
            'restrictToAuthorizedDevices': isBool}},
        'drive_and_docs_drive_sdk': {'reducer': _merge_reducer,
                                     'settings': {
                                         'enableDriveSdkApiAccess': isBool}},
        'drive_and_docs_external_sharing': {'settings': {
            'accessCheckerSuggestions': isEnum,
            'allowNonGoogleInvites': isBool,
            'allowNonGoogleInvitesInAllowlistedDomains': isBool,
            'allowPublishingFiles': isBool,
            'allowReceivingExternalFiles': isBool,
            'allowReceivingFilesOutsideAllowlistedDomains': isBool,
            'allowedPartiesForDistributingContent': isEnum,
            'externalSharingMode': isEnum,
            'warnForExternalSharing': isBool,
            'warnForSharingOutsideAllowlistedDomains': isBool}},
        'drive_and_docs_general_access_default': {'settings': {
            'defaultFileAccess': isEnum}},
        'drive_and_docs_service_status': {'settings': {
            'serviceState': isState}},
        'drive_and_docs_shared_drive_creation': {'settings': {
            'allowContentManagersToShareFolders': isBool,
            'allowExternalUserAccess': isBool,
            'allowManagersToOverrideSettings': isBool,
            'allowNonMemberAccess': isBool,
            'allowSharedDriveCreation': isBool,
            'allowedPartiesForDownloadPrintCopy': isEnum,
            'orgUnitForNewSharedDrives': isEnum}},
        'drive_and_docs_file_security_update': {'settings': {
            'allowUsersToManageUpdate': isBool,
            'securityUpdate': isEnum}},
        'enterprise_service_restrictions_service_status': {'settings': {
            'serviceState': isState}},
        'gmail_auto_forwarding': {'settings': {'enableAutoForwarding': isBool}},
        'gmail_email_attachment_safety': {'settings': {
            'anomalousAttachmentProtectionConsequence': isEnum,
            'applyFutureRecommendedSettingsAutomatically': isBool,
            'attachmentWithScriptsProtectionConsequence': isEnum,
            'enableAnomalousAttachmentProtection': isBool,
            'enableAttachmentWithScriptsProtection': isBool,
            'enableEncryptedAttachmentProtection': isBool,
            'encryptedAttachmentProtectionConsequence': isEnum}},
        'gmail_email_spam_filter_ip_allowlist': {'settings': {
            'allowedIpAddresses': isListStrings}},
        'gmail_enhanced_pre_delivery_message_scanning': {'settings': {
            'enableImprovedSuspiciousContentDetection': isBool}},
        'gmail_imap_access': {'settings': {'enableImapAccess': isBool}},
        'gmail_links_and_external_images': {'settings': {
            'applyFutureSettingsAutomatically': isBool,
            'enableAggressiveWarningsOnUntrustedLinks': isBool,
            'enableExternalImageScanning': isBool,
            'enableShortenerScanning': isBool}},
        'gmail_mail_delegation': {'settings': {'enableMailDelegation': isBool}},
        'gmail_pop_access': {'settings': {'enablePopAccess': isBool}},
        'gmail_service_status': {'settings': {'serviceState': isState}},
        'gmail_spoofing_and_authentication': {'settings': {
            'applyFutureSettingsAutomatically': isBool,
            'detectDomainNameSpoofing': isBool,
            'detectDomainSpoofingFromUnauthenticatedSenders': isBool,
            'detectEmployeeNameSpoofing': isBool,
            'detectGroupsSpoofing': isBool,
            'detectUnauthenticatedEmails': isBool,
            'domainNameSpoofingConsequence': isEnum,
            'domainSpoofingConsequence': isEnum,
            'employeeNameSpoofingConsequence': isEnum,
            'groupsSpoofingConsequence': isEnum,
            'unauthenticatedEmailConsequence': isEnum}},
        'gmail_user_email_uploads': {'settings': {
            'enableMailAndContactsImport': isBool}},
        'gmail_workspace_sync_for_outlook': {'settings': {
            'enableGoogleWorkspaceSyncForMicrosoftOutlook': isBool}},
        'groups_for_business_groups_sharing': {'reducer': _merge_reducer,
                                               'settings': {
            'collaborationCapability': isEnum,
            'createGroupsAccessLevel': isEnum,
            'newGroupsAreHidden': isBool,
            'ownersCanAllowExternalMembers': isBool,
            'ownersCanAllowIncomingMailFromPublic': isBool,
            'ownersCanHideGroups': isBool,
            'viewTopicsDefaultAccessLevel': isEnum}},
        'groups_for_business_service_status': {'settings': {
            'serviceState': isState}},
        'jamboard_service_status': {'settings': {'serviceState': isState}},
        'keep_service_status': {'settings': {'serviceState': isState}},
        'location_history_user_takeout': {'settings': {
            'takeoutStatus': isEnum}},
        'maps_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'meet_safety_access': {'settings': {'meetingsAllowedToJoin': isEnum}},
        'meet_safety_domain': {'settings': {'usersAllowedToJoin': isEnum}},
        'meet_safety_external_participants': {'settings': {
            'enableExternalLabel': isBool}},
        'meet_safety_host_management': {'settings': {
            'enableHostManagement': isBool}},
        'meet_service_status': {'settings': {'serviceState': isState}},
        'meet_video_recording': {'settings': {'enableRecording': isBool}},
        'migrate_service_status': {'settings': {'serviceState': isState}},
        'pay_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'photos_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'play_console_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'play_user_takeout': {'settings': {'takeoutStatus': isEnum}},
        'security_advanced_protection_program': {'settings': {
            'enableAdvancedProtectionSelfEnrollment': isBool,
            'securityCodeOption': isEnum}},
        'security_less_secure_apps': {'reducer': _merge_reducer,
                                      'settings': {
                                          'allowLessSecureApps': isBool}},
        'security_login_challenges': {'settings': {
            'enableEmployeeIdChallenge': isBool}},
        'security_password': {'settings': {
            'allowedStrength': isEnum,
            'allowReuse': isBool,
            'enforceRequirementsAtLogin': isBool,
            'expirationDuration': isDuration,
            'maximumLength': isInt,
            'minimumLength': isInt}},
        'security_session_controls': {'settings': {
            'webSessionDuration': isDuration}},
        'security_super_admin_account_recovery': {'reducer': _merge_reducer,
                                                  'settings': {
            'enableAccountRecovery': isBool}},
        'security_two_step_verification_device_trust': {'settings': {
            'allowTrustingDevice': isBool}},
        'security_two_step_verification_enforcement': {'settings': {
            'enforcedFrom': isTimestamp}},
        'security_two_step_verification_enforcement_factor': {'settings': {
            'allowedSignInFactorSet': isEnum}},
        'security_two_step_verification_enrollment': {'settings': {
            'allowEnrollment': isBool}},
        'security_two_step_verification_grace_period': {'settings': {
            'enrollmentGracePeriod': isDuration}},
        'security_user_account_recovery': {'reducer': _merge_reducer,
                                           'settings': {
            'enableAccountRecovery': isBool}},
        'sites_service_status': {'settings': {'serviceState': isState}},
        'sites_sites_creation_and_modification': {'settings': {
            'allowSitesCreation': isBool,
            'allowSitesModification': isBool}},
        'takeout_service_status': {'settings': {'serviceState': isState}},
        'tasks_service_status': {'settings': {'serviceState': isState}},
        'vault_service_status': {'settings': {'serviceState': isState}},
        'workspace_marketplace_apps_access_options': {'settings': {
            'accessLevel': isEnum,
            'allowAllInternalApps': isBool}},
        'youtube_user_takeout': {'settings': {'takeoutStatus': isEnum}}}

    # In this section of Google's Policy API documentation:
    # https://cloud.google.com/identity/docs/concepts/policy-api-concepts
    # #default_field_values
    # there are a number of settings which may not be present in the top-level
    # orgunit, and for these cases defaults must be applied.  The following
    # default values are taken directly from the documentation.  Google claims
    # that it would take an act of god to change these defaults, but since
    # these are copied from an external source, there is a risk that one or
    # more defaults may be changed.  There is also no assurance that Google's
    # documentation reflects the current default values (i.e., the
    # documented defaults must be kept current with the implementation).

    _defaults = {
        'calendar_external_invitations': {'warnOnInvite': True},
        'chat_chat_history': {'allowUserModification': True,
                              'historyOnByDefault': False},
        'chat_external_chat_restriction': {
            'allowExternalChat': False,
            'externalChatRestriction': 'NO_RESTRICTION'},
        'drive_and_docs_drive_sdk': {'enableDriveSdkApiAccess': True},
        'drive_and_docs_external_sharing': {
            'accessCheckerSuggestions': 'RECIPIENTS_OR_AUDIENCE_OR_PUBLIC',
            'allowNonGoogleInvites': True,
            'allowNonGoogleInvitesInAllowlistedDomains': False,
            'allowPublishingFiles': True,
            'allowReceivingExternalFiles': True,
            'allowReceivingFilesOutsideAllowlistedDomains': True,
            'allowedPartiesForDistributingContent': 'ALL_ELIGIBLE_USERS',
            'externalSharingMode': 'ALLOWED',
            'warnForExternalSharing': True,
            'warnForSharingOutsideAllowlistedDomains': True},
        'drive_and_docs_general_access_default': {
            'defaultFileAccess': 'LINK_SHARING_PRIVATE'},
        'gmail_workspace_sync_for_outlook': {
            'enableGoogleWorkspaceSyncForMicrosoftOutlook': True},
        'gmail_email_spam_filter_ip_allowlist': {
            'allowedIpAddresses': []},
        'gmail_links_and_external_images': {
            'applyFutureSettingsAutomatically': True,
            'enableAggressiveWarningsOnUntrustedLinks': False},
        'gmail_spoofing_and_authentication': {
            'applyFutureSettingsAutomatically': True},
        'groups_for_business_groups_sharing': {
            'collaborationCapability': 'DOMAIN_USERS_ONLY',
            'createGroupsAccessLevel': 'USERS_IN_DOMAIN',
            'newGroupsAreHidden': False,
            'ownersCanAllowExternalMembers': False,
            'ownersCanAllowIncomingMailFromPublic': True,
            'ownersCanHideGroups': False,
            'viewTopicsDefaultAccessLevel': 'DOMAIN_USERS'},
        'security_less_secure_apps': {'allowLessSecureApps': False},
        'security_super_admin_account_recovery': {
            'enableAccountRecovery': False},
        'security_user_account_recovery': {'enableAccountRecovery': False},
        'workspace_marketplace_apps_access_options': {
            'accessLevel': 'ALLOW_ALL',
            'allowAllInternalApps': False},
    }

    # This is the URL to the Policies API.
    _baseURL = 'https://cloudidentity.googleapis.com/v1/policies'
    _too_many_requests = 429

    def __init__(self, gws_auth: GwsAuth, top_orgunit: str):

        """PolicyAPI class instance initialization.

        :param GwsAuth gws_auth: GWS credentials instance.
        :param str top_orgunit: name of the top-level orgunit.
        """

        # Google's AuthorizedSession is currently being used because this
        # API is not available in the Google API Client interface.
        self._session = AuthorizedSession(gws_auth.credentials)

        self._top_orgunit = top_orgunit

        # This is a mapping of Google's org unit ids to names.
        self._orgunit_id_map = self._get_ou()

        self._group_id_map = self._get_groups()

        # This is a dictionary that is used in reducing the policies returned
        # by Google.
        self._reduction_map = None

    def __enter__(self):

        # This class is implemented as a context manager - meaning that it's
        # intended to be instantiated via the "with" statement.  This ensures
        # that the Google resource will be properly closed.

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        self.close()

    def close(self):

        """Closes Google's resource.  This should be called when the instance
        is no longer needed.
        """

        self._session.close()

    def get_policies(self) -> dict:

        """Query Google's Policy API and return the policy settings grouped
        by org unit.

        :return: dictionary of settings, with keys being the org unit names
            and the values are dictionaries with name/value pairs for the
            settings.
        :rtype: dict
        """

        # Google returns the policy settings in a dictionary.  Each setting
        # contains one or more values and is associated with an org unit.
        policies = self._get_policies_list()

        # If the following environment variable is defined, the policy data
        # returned by Google, as well as the orgunit and group maps, will be
        # written to the file name defined in the variable.  If the value
        # contains only whitespace, the data will be written to the standard
        # output stream.  This is intended for debugging.
        dump_envname = 'SCUBAGOGGLES_DUMP_FILE'
        if dump_envname in os.environ:
            self._dump(policies, os.environ[dump_envname].strip())

        self._reduce(policies)

        result = defaultdict(dict)

        for key, policy in self._reduction_map.items():
            orgunit_name, section = key
            result[orgunit_name][section] = self._settings(policy)

        self._apply_defaults(result)

        return result

    def _get_ou(self) -> dict:

        """Calls Google's Directory API to get all org units, and returns a
        mapping of org unit id to name.

        :return: dictionary with the Google org unit identifier as the key,
            and the corresponding name as the value.
        :rtype: dict
        """

        # See comment above regarding the Policy API not currently included
        # in Google's Client API.  While the directory API is included in the
        # Client API, it's easiest here to use the same mechanism as is used
        # for the Policy API.
        url = ('https://admin.googleapis.com/admin/directory/'
               'v1/customer/my_customer/orgunits')

        params = {'orgUnitPath': '/',
                  'type': 'all_including_parent'}

        response = self._get(url, params)

        # Based on the Client API, there should be no possibility of a next
        # page when getting the org units, but this check is here just in
        # case.
        if 'nextPageToken' in response:
            raise RuntimeError(f'{url} - unhandled next page token')

        orgunit_id_map = {}

        for orgunit_data in response['organizationUnits']:
            orgunit_id = orgunit_data['orgUnitId'].removeprefix('id:')
            orgunit_id_map[orgunit_id] = {'name': orgunit_data['name'],
                                          'path': orgunit_data['orgUnitPath']}

        return orgunit_id_map

    def _get_groups(self) -> dict:

        """Calls Google's Directory API to get all groups in the root org unit,
        and returns a mapping of group id to name.

        :return: dictionary with the Google group identifier as the key,
            and the corresponding name as the value.
        :rtype: dict
        """

        # See comment above regarding the Policy API not currently included
        # in Google's Client API.  While the directory API is included in the
        # Client API, it's easiest here to use the same mechanism as is used
        # for the Policy API.
        url = 'https://admin.googleapis.com/admin/directory/v1/groups'

        group_id_map = {}

        params = {'customer': 'my_customer'}

        while True:

            response = self._get(url, params)

            for group_data in response.get('groups', ()):
                group_id = group_data['id']
                group_id_map[group_id] = group_data['name']

            if 'nextPageToken' not in response:
                break

            params['pageToken'] = response['nextPageToken']

        return group_id_map

    def _get_policies_list(self) -> list:

        """Calls the Google Policy API and returns the results.

        :return: list of dictionaries containing policy settings.
        :rtype: list
        """

        policies = []

        # The parameters will only be used if Google returns the policies in
        # multiple pages.  The following loop will iterate multiple times only
        # if there's more than one page.
        params = None

        while True:

            policies_result = self._get(self._baseURL, params)

            # So far, only one page of actual content is being returned
            # (with 2 blank pages, which is another issue).  Merge each page's
            # policies in with the result list.
            if 'policies' in policies_result:
                policies += policies_result['policies']

            if 'nextPageToken' not in policies_result:
                break

            params = {'pageToken': policies_result['nextPageToken']}

        return policies

    def _get(self, url: str, params: dict = None) -> dict:

        """Invokes a GET request using the given URL, returning the result.

        :param str url: URL
        :param dict params: [optional] parameters to be used in the request.

        :return: dictionary result returned by the Google request.
        :rtype: dict
        """

        response = None

        start_time = time.time()

        # Google will return the "too many requests" error if the requests come
        # in without any delay between them. The total iterations is limited to
        # 8 because the delay is exponential and after several iterations the
        # delay becomes impractical if the error continues to be returned.
        # In practice, with the API calls it sometimes takes seconds to get a
        # response, and for those cases a subsequent request is made after a
        # sufficient delay due to the time it took for the previous response.

        for iter_count in range(1, 9):

            response = self._session.get(url, params = params)
            if response.status_code != self._too_many_requests:
                break

            # Back off the requests exponentially (adding up to a 10% random
            # delay).

            delay = (2 ** iter_count) / 10
            delay += (delay * random())

            log.debug('attempt %i - too many requests response: '
                      'delay %.2f seconds', iter_count, delay)

            sleep(delay)

        end_time = time.time() - start_time

        response_json = response.json()

        if not response.ok:
            raise RuntimeError(f'? {url} - {response_json["error"]["message"]}')

        log.debug('URL: %s', url)
        if params:
            log.debug('  params: %s', params)
        log.debug('Result length: %d', len(response.text))
        log.debug('Elapsed time: %.2f seconds', end_time)

        return response_json

    def _reduce(self, policies: Iterable):

        """Reduces the policies returned by Google to those that apply for
        each orgunit and group.

        This method populates the instance's "_reduction_map".  It is a
        dictionary where the key is a tuple containing the orgunit/group name
        and section name.  The value is a policy (dictionary).  After the
        reduction, there will be only one policy for each section in an
        orgunit/group.

        See https://cloud.google.com/identity/docs/concepts/policy-api-concepts
            #reducers_for_settings
        for Google's discussion of the "reduction process".

        :param list policies: list of policies (dictionaries).
        """

        self._reduction_map = {}

        # Sorting the policies by largest sort order first is KEY to getting
        # the correct policies.  This accomplishes the "max" reduction
        # referred to by Google, and it also necessary for the "merge"
        # reduction.
        policies.sort(key = self._sort_order, reverse = True)

        for policy in policies:

            # For the current policy setting, use the returned org unit id
            # to get the org unit name, which is used as the key for the
            # result dictionary.

            if 'orgUnit' in policy['policyQuery']:
                orgunit_id = policy['policyQuery']['orgUnit']
                orgunit_id = orgunit_id.removeprefix('orgUnits/')
                orgunit_data = self._orgunit_id_map[orgunit_id]
                orgunit_name = orgunit_data['name']
                path = orgunit_data['path']
                if len(path) > 1 and orgunit_name != path[1:]:
                    # The orgunit is below the first level of orgunits in the
                    # hierarchy.  The name will include the following suffix
                    # that shows the parent hierarchy where it belongs so it can
                    # be identified, particularly if the same name is used
                    # in different suborgunit hierarchies.
                    parent = path[1:].removesuffix(f'/{orgunit_name}')
                    orgunit_name += f' (in {parent})'
            else:
                # NOTE: a policy setting should always be associated with
                # an org unit.  In rare cases, an org unit is not provided,
                # and in this case the policy is associated with the top-level
                # org unit.
                log.debug('Org unit data missing for "%s", '
                          'assuming top-level OU.',
                          policy['setting']['type'])
                orgunit_name = self._top_orgunit

            if 'group' in policy['policyQuery']:
                group_id = policy['policyQuery']['group']
                group_id = group_id.removeprefix('groups/')
                # NOTE: the get() handles the case where Google returns
                # something that doesn't conform to their documented format
                # (i.e., 'groups/<group-id>').  For example, Google will
                # return "WORKSPACE_ALL_ADMIN_GROUP" as a value in some
                # cases.  If the group id value doesn't conform to the
                # expected format, the value is kept as received as the
                # group name.
                group_name = self._group_id_map.get(group_id, group_id)
                orgunit_name += f' (group "{group_name}")'

            # The setting has two layers in the policies dictionary.  Depending
            # on the setting, there may be one or multiple values - so the
            # setting itself has a "type" (i.e., "name), and the value is a
            # dictionary with one or more name/value pairs.  The setting type
            # is something like "settings/appsheet.service_status".  We remove
            # the "settings/" prefix and convert the dot to an underscore.
            # This results in "appsheet_service_status", which is a format that
            # can easily be used in Rego code.
            policy_setting = policy['setting']
            section = policy_setting['type'].removeprefix('settings/')
            section = section.replace('.', '_')

            key = (orgunit_name, section)

            # This is where the dictionary is populated, with policies
            # having the highest sort order for each orgunit/group and
            # section.  This is possible because of the initial sorting
            # above.
            if key not in self._reduction_map:
                self._reduction_map[key] = policy
                continue

            expected_settings = self._expectedPolicySettings.get(section)

            if not expected_settings:
                # The section is not in the expected settings, which means
                # it is not associated with a secure baseline.
                continue

            # If there is a reducer associated with this policy, it will
            # be invoked.
            reduce_name = expected_settings.get('reduce_method')

            if reduce_name:
                reduce_method = getattr(self, reduce_name)
                reduce_method(key, policy)

    @staticmethod
    def _settings(policy: dict) -> dict:

        """Given a policy (dictionary) from Google's response, returns the
        name/value pairs, which are the setting values for a section.

        :param policy: "raw" policy data dictionary returned by Google.
        """

        return policy['setting']['value']

    @staticmethod
    def _sort_order(policy: dict) -> float:

        """Given a policy (dictionary) from Google's response, returns the
        sort order value for the policy.

        :param policy: "raw" policy data dictionary returned by Google.
        """

        return policy['policyQuery']['sortOrder']

    def _merge(self, key: tuple, policy: dict):

        """Peforms a merge reduction of the given policy with the current
        policy (having the greatest sort order).

        :param key: tuple containing the orgunit name and section name, used
            for locating the corresponding policy in the reduction map.
        :param policy: "raw" policy having a sort order below the policy
            stored in the reduction map.
        """

        # Get the policy from the reduction map.  The policies have already
        # been sorted by largest sort order first, so this one is the
        # in-effect policy for the given key.

        current_policy = self._reduction_map[key]

        current_settings = self._settings(current_policy)

        # If any setting present in the given lower sort order policy is
        # not present in the in-effect policy, add the setting to the
        # current policy.

        for setting, value in self._settings(policy).items():
            if setting not in current_settings:
                current_settings[setting] = value

    def _apply_defaults(self, policies: dict):

        """Applies Google's default setting values to the top orgunit policies.
        See the discussion above where the default setting values are defined.

        :param policies: the complete set of policies, formatted from the raw
            data returned by Google.
        """

        if not self._top_orgunit:
            log.debug('No top orgunit specified in PolicyAPI - '
                      'skipping defaults')
            return

        # The defaults apply only to the top-level orgunit.  The top orgunit
        # must contain all settings, and the subordinate orgunits and groups
        # only contain settings that have changed from the top orgunit's
        # values.

        top_ou_policies = policies[self._top_orgunit]

        # For some GWS tenants, there may be inactive SKUs for certain
        # applications.  For example, the customer may not have an active
        # SKU that allows them to use the Vault service.  In this case, there
        # will be no "vault_service_status" returned by the Policy API.
        # According to Google, any missing service status is due to the
        # customer not subscribing to the service, so we can assume
        # that the service is disabled.

        missing_service_status = sorted(s for s in self._expectedPolicySettings
                                  if s.endswith('_service_status')
                                  and s not in top_ou_policies)

        for section in missing_service_status:
            top_ou_policies[section] = {'serviceState': 'DISABLED'}

        if missing_service_status:
            log.debug('%s: %s - service status missing (assumed DISABLED)',
                      self._top_orgunit,
                      ', '.join(s.removesuffix('_service_status')
                                for s in missing_service_status))

        # We'll keep track of the default settings actually applied so they can
        # be reported in the log.

        applied = defaultdict(dict)

        for section, settings in self._defaults.items():
            if section not in top_ou_policies:
                # Copy the section dictionary into the top OU policies as a
                # precaution because the defaults are read-only.
                top_ou_policies[section] = settings.copy()
                applied[section] = settings
                continue

            for setting, value in settings.items():
                if setting not in top_ou_policies[section]:
                    top_ou_policies[section][setting] = value
                    applied[section][setting] = value

        if applied:
            log.debug('Default value(s) applied to %s:', self._top_orgunit)
            for section, settings in applied.items():
                log.debug('  %s:', section)
                for setting, value in settings.items():
                    log.debug('    %s: %s', setting, str(value))

    def _dump(self, policies: Iterable, file_or_stream = sys.stdout):

        """Writes the orgunit and group maps, and the given policies from
        Google to the given I/O stream or file.

        :param policies: sequence of policy data (dictionaries) returned by
            Google's Policy API.
        :param file_or_stream: [optional] file specification for the file
            to be written, or an existing I/O stream.  If not given or if
            an empty string is provided, the standard output stream (stdout)
            is used.
        """

        out_data = {'orgunits': self._orgunit_id_map,
                    'groups': self._group_id_map,
                    'policies': policies}

        is_stream = not file_or_stream or isinstance(file_or_stream, io.IOBase)

        # pylint: disable=consider-using-with
        out_stream = (sys.stdout if not file_or_stream
                      else file_or_stream if is_stream
                      else Path(file_or_stream).open('wt', encoding = 'utf-8'))

        try:
            json.dump(out_data, out_stream, indent = 2)
        finally:
            if not is_stream:
                out_stream.close()

    def verify(self, policies: dict) -> set:

        """Verify that all expected policy settings (see above) are present
        for the top-level orgunit, and that the values of each setting are the
        correct type and/or format.

        We do this verification because while Rego is good at checking for
        policy requirements, it may yield incorrect results when expected
        settings are missing or values are incorrect.  If any settings that are
        missing, checks should be done to determine what's wrong with the data
        returned by the API.

        :param dict policies: policy settings returned by get_policies().
        :return: A set containing any missing settings or settings with invalid
            values.
        """

        orgunit = self._top_orgunit

        expected_policy_settings = self._expectedPolicySettings
        orgunit_policies = policies.get(orgunit)

        if not orgunit_policies:
            log.warning('No policy settings found for orgunit: %s', orgunit)
            return set()

        missing_settings = set()
        invalid_settings = set()

        for section, section_data in expected_policy_settings.items():

            expected_settings = section_data['settings']
            settings = orgunit_policies.get(section)
            if not settings:
                for expected_setting in expected_settings:
                    missing_settings.add(f'{section}.{expected_setting}')
                continue

            for setting_name, verifier in expected_settings.items():
                policy_value = settings.get(setting_name)
                if policy_value is None:
                    missing_settings.add(f'{section}.{setting_name}')
                elif not verifier(policy_value):
                    invalid_settings.add(f'{section}.{setting_name}')

        return missing_settings.union(invalid_settings)
