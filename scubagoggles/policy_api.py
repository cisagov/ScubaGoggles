"""Google Policy API class implementation
"""

import logging
import re

from collections import defaultdict
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

    # This is the complete list of policy settings returned by Google.
    # The key is the setting type (NOTE that while Google returns a
    # setting type with a period (.) delimiting the type (e.g.,
    # "sites.service_status"), we convert the periods into underscores because
    # Rego uses the period to delimit hierarchy).  The value is a dictionary
    # containing the name of each setting and a function that will validate
    # that the setting value is correct.


    _expectedPolicySettings = {
        'analytics_service_status': {'serviceState': isState},
        'applied_digital_skills_service_status': {'serviceState': isState},
        'appsheet_service_status': {'serviceState': isState},
        'blogger_service_status': {'serviceState': isState},
        'blogger_user_takeout': {'takeoutStatus': isEnum},
        'books_user_takeout': {'takeoutStatus': isEnum},
        'calendar_appointment_schedules': {'enablePayments': isBool},
        'calendar_external_invitations': {'warnOnInvite': isBool},
        'calendar_interoperability': {
            'enableExchangeRoomBooking': isBool,
            'enableFullEventDetails': isBool,
            'enableInteroperability': isBool},
        'calendar_primary_calendar_max_allowed_external_sharing': {
            'maxAllowedExternalSharing': isEnum},
        'calendar_secondary_calendar_max_allowed_external_sharing': {
            'maxAllowedExternalSharing': isEnum},
        'calendar_service_status': {'serviceState': isState},
        'chat_chat_file_sharing': {
            'externalFileSharing': isEnum,
            'internalFileSharing': isEnum},
        'chat_chat_history': {
            'allowUserModification': isBool,
                'historyOnByDefault': isBool},
        'chat_external_chat_restriction': {
            'allowExternalChat': isBool,
            'externalChatRestriction': isEnum},
        'chat_service_status': {'serviceState': isState},
        'chat_space_history': {'historyState': isEnum},
        'chrome_canvas_service_status': {'serviceState': isState},
        'classroom_api_data_access': {'enableApiAccess': isBool},
        'classroom_class_membership': {
            'whoCanJoinClasses': isEnum,
            'whichClassesCanUsersJoin': isEnum},
        'classroom_guardian_access': {
            'allowAccess': isBool,
            'whoCanManageGuardianAccess': isEnum},
        'classroom_roster_import': {'rosterImportOption': isEnum},
        'classroom_student_unenrollment': {'whoCanUnenrollStudents': isEnum},
        'classroom_teacher_permissions': {'whoCanCreateClasses': isEnum},
        'cloud_search_service_status': {'serviceState': isState},
        'drive_and_docs_drive_for_desktop': {
            'allowDriveForDesktop': isBool,
            'restrictToAuthorizedDevices': isBool},
        'drive_and_docs_drive_sdk': {'enableDriveSdkApiAccess': isBool},
        'drive_and_docs_external_sharing': {
            'accessCheckerSuggestions': isEnum,
            'allowNonGoogleInvites': isBool,
            'allowNonGoogleInvitesInAllowlistedDomains': isBool,
            'allowPublishingFiles': isBool,
            'allowReceivingExternalFiles': isBool,
            'allowReceivingFilesOutsideAllowlistedDomains': isBool,
            'allowedPartiesForDistributingContent': isEnum,
            'externalSharingMode': isEnum,
            'warnForExternalSharing': isBool,
            'warnForSharingOutsideAllowlistedDomains': isBool},
        'drive_and_docs_general_access_default': {'defaultFileAccess': isEnum},
        'drive_and_docs_service_status': {'serviceState': isState},
        'drive_and_docs_shared_drive_creation': {
            'allowContentManagersToShareFolders': isBool,
            'allowExternalUserAccess': isBool,
            'allowManagersToOverrideSettings': isBool,
            'allowNonMemberAccess': isBool,
            'allowSharedDriveCreation': isBool,
            'allowedPartiesForDownloadPrintCopy': isEnum,
            'orgUnitForNewSharedDrives': isEnum},
        'drive_and_docs_file_security_update': {
            'allowUsersToManageUpdate': isBool,
            'securityUpdate': isEnum},
        'enterprise_service_restrictions_service_status': {
            'serviceState': isState},
        'gmail_auto_forwarding': {'enableAutoForwarding': isBool},
        'gmail_email_attachment_safety': {
            'anomalousAttachmentProtectionConsequence': isEnum,
            'applyFutureRecommendedSettingsAutomatically': isBool,
            'attachmentWithScriptsProtectionConsequence': isEnum,
            'enableAnomalousAttachmentProtection': isBool,
            'enableAttachmentWithScriptsProtection': isBool,
            'enableEncryptedAttachmentProtection': isBool,
            'encryptedAttachmentProtectionConsequence': isEnum},
        'gmail_email_spam_filter_ip_allowlist': {
            'allowedIpAddresses': isListStrings},
        'gmail_enhanced_pre_delivery_message_scanning': {
            'enableImprovedSuspiciousContentDetection': isBool},
        'gmail_links_and_external_images': {
            'applyFutureSettingsAutomatically': isBool,
            'enableAggressiveWarningsOnUntrustedLinks': isBool,
            'enableExternalImageScanning': isBool,
            'enableShortenerScanning': isBool},
        'gmail_service_status': {'serviceState': isState},
        'gmail_spoofing_and_authentication': {
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
            'unauthenticatedEmailConsequence': isEnum},
        'groups_for_business_groups_sharing': {
            'collaborationCapability': isEnum,
            'createGroupsAccessLevel': isEnum,
            'newGroupsAreHidden': isBool,
            'ownersCanAllowExternalMembers': isBool,
            'ownersCanAllowIncomingMailFromPublic': isBool,
            'ownersCanHideGroups': isBool,
            'viewTopicsDefaultAccessLevel': isEnum},
        'groups_for_business_service_status': {'serviceState': isState},
        'jamboard_service_status': {'serviceState': isState},
        'keep_service_status': {'serviceState': isState},
        'location_history_user_takeout': {'takeoutStatus': isEnum},
        'maps_user_takeout': {'takeoutStatus': isEnum},
        'meet_safety_access': {'meetingsAllowedToJoin': isEnum},
        'meet_safety_domain': {'usersAllowedToJoin': isEnum},
        'meet_safety_external_participants': {'enableExternalLabel': isBool},
        'meet_safety_host_management': {'enableHostManagement': isBool},
        'meet_service_status': {'serviceState': isState},
        'meet_video_recording': {'enableRecording': isBool},
        'migrate_service_status': {'serviceState': isState},
        'pay_user_takeout': {'takeoutStatus': isEnum},
        'photos_user_takeout': {'takeoutStatus': isEnum},
        'play_console_user_takeout': {'takeoutStatus': isEnum},
        'play_user_takeout': {'takeoutStatus': isEnum},
        'security_advanced_protection_program': {
            'enableAdvancedProtectionSelfEnrollment': isBool,
            'securityCodeOption': isEnum},
        'security_less_secure_apps': {'allowLessSecureApps': isBool},
        'security_login_challenges': {'enableEmployeeIdChallenge': isBool},
        'security_password': {
            'allowedStrength': isEnum,
            'allowReuse': isBool,
            'enforceRequirementsAtLogin': isBool,
            'expirationDuration': isDuration,
            'maximumLength': isInt,
            'minimumLength': isInt},
        'security_session_controls': {'webSessionDuration': isDuration},
        'security_super_admin_account_recovery': {
            'enableAccountRecovery': isBool},
        'security_user_account_recovery': {'enableAccountRecovery': isBool},
        'sites_service_status': {'serviceState': isState},
        'sites_sites_creation_and_modification': {
            'allowSitesCreation': isBool,
            'allowSitesModification': isBool},
        'tasks_service_status': {'serviceState': isState},
        'vault_service_status': {'serviceState': isState},
        'workspace_marketplace_apps_access_options': {
            'accessLevel': isEnum,
            'allowAllInternalApps': isBool},
        'youtube_user_takeout': {'takeoutStatus': isEnum}}

    # This is the URL to the Policies API.
    _baseURL = 'https://cloudidentity.googleapis.com/v1beta1/policies'
    _too_many_requests = 429

    def __init__(self, gws_auth: GwsAuth):

        """PolicyAPI class instance initialization

        :param GwsAuth gws_auth: GWS credentials instance.
        """

        # Google's AuthorizedSession is currently being used because this
        # API is not available in the Google API Client interface.
        self._session = AuthorizedSession(gws_auth.credentials)

        # This is a mapping of Google's org unit ids to names.
        self._orgunit_id_map = self._get_ou()

        self._group_id_map = self._get_groups()

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

        result = defaultdict(dict)

        for policy in policies:

            # For the current policy setting, use the returned org unit id
            # to get the org unit name, which is used as the key for the
            # result dictionary.
            orgunit_id = policy['policyQuery']['orgUnit']
            orgunit_id = orgunit_id.removeprefix('orgUnits/')
            orgunit_name = self._orgunit_id_map[orgunit_id]['name']

            if 'group' in policy['policyQuery']:
                group_id = policy['policyQuery']['group']
                group_id = group_id.removeprefix('groups/')
                group_name = self._group_id_map[group_id]
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
            setting_type = policy_setting['type'].removeprefix('settings/')
            setting_type = setting_type.replace('.', '_')
            setting_value = policy_setting['value']

            result[orgunit_name][setting_type] = setting_value

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

            for group_data in response['groups']:
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

        # Google will return the "too many requests" error if the requests
        # come in without any delay between them.  Is there a better way than
        # having to delay (like telling Google up front how many requests
        # we'll be making in a row, or is it a "quota" that needs to be
        # adjusted??)? Anyway, the following loop implements the delay.  The
        # total iterations is limited to 8 because the delay is exponential
        # and after several iterations the delay becomes impractical if the
        # error continues to be returned.
        #
        # Subsequent note: this may not be necessary because we're now making
        # only 1 (with possible next page requests) call, and it's doubtful
        # that this would trigger a "too many requests" response.  However,
        # it's here in case it's needed.

        for iter_count in range(8):

            response = self._session.get(url, params = params)
            if response.status_code != self._too_many_requests:
                break

            # Back off the requests exponentially (adding up to a 10% random
            # delay).

            delay = (2 ** iter_count) / 10
            delay += (delay * random())

            log.debug('attempt %i - too many requests response: '
                      'delay %i seconds', iter_count + 1, delay)

            sleep(delay)

        response_json = response.json()

        if not response.ok:
            raise RuntimeError(f'? {url} - {response_json["error"]["message"]}')

        return response.json()

    def verify(self, orgunit, policies):

        """Verify that all expected policy settings (see above) are present
        for the given orgunit (i.e., the top orgunit), and that the values of
        each setting are the correct type and/or format.

        We do this verification because while Rego is good at checking for
        policy requirements, it may yield incorrect results when expected
        settings are missing or values are incorrect.  This verification
        only issues warnings. so we're not aborting if something is found
        to be missing or incorrect.  However, if warnings are issued,
        checks should be done to determine what's wrong with the data returned
        by Google.

        :param str orgunit: name of the top-level orgunit.
        :param dict policies: policy settings returned by get_policies().
        :return: True if all expected policy settings are found and the
            setting values are correct types and format.
        """

        policies_ok = True

        expected_settings = self._expectedPolicySettings
        orgunit_policies = policies.get(orgunit)

        if not orgunit_policies:
            log.warning('No policy settings found for orgunit: %s', orgunit)
            return False

        missing_settings = {n for n in expected_settings
                            if n not in orgunit_policies}

        # Temporary section: Google's API had an issue in the alpha version
        # where all the service status settings were missing.  These are
        # used (necessary) in the Rego code, so as a workaround, the
        # service status is assumed to be "enabled" if it is missing (except
        # for sites, which has a baseline requirment that it be disabled).
        # Although this code won't do anything once this bug is fixed by
        # Google, this section should probably be removed when no longer
        # needed.

        missing_service_status = {n for n in missing_settings
                                  if n.endswith('_service_status')
                                     and not n.startswith('sites_')}

        if missing_service_status:
            for key in missing_service_status:
                orgunit_policies[key] = {'serviceState': 'ENABLED'}

            log.warning('Service status setting(s) missing - '
                        'assumed enabled: %s',
                        missing_service_status)
            missing_settings -= missing_service_status

        # End temporary section

        if missing_settings:
            log.warning('Setting(s) missing from %s orgunit: %s',
                        orgunit,
                        str(sorted(missing_settings)))
            policies_ok = False

        for resource_name, expected_settings in expected_settings.items():

            settings = orgunit_policies.get(resource_name)
            if not settings:
                continue

            invalid_settings = []

            for setting_name, verifier in expected_settings.items():
                policy_value = settings.get(setting_name)
                if policy_value is None or not verifier(policy_value):
                    invalid_settings.append(setting_name)

            if invalid_settings:
                log.warning('Settings missing or values invalid for '
                            'orgunit %s, resource %s: %s',
                            orgunit,
                            resource_name,
                            sorted(invalid_settings))

        return policies_ok
