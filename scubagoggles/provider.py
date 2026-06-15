# pylint: disable=too-many-lines
"""
provider.py is where the GWS api calls are made.
"""

import logging
import warnings
from typing import Callable, ContextManager, Mapping, Optional, Protocol
from pathlib import Path
from tqdm import tqdm

from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError
import google.auth.transport.requests as auth_requests
from scubagoggles.auth import GwsAuth
from scubagoggles.policy_api import PolicyAPI
from scubagoggles.utils import create_subset_inverted_dict, \
    create_key_to_list, merge_dicts
from scubagoggles.scuba_constants import ApiReference
from scubagoggles.robust_dns import RobustDNSClient

log = logging.getLogger(__name__)

# pylint: disable=too-few-public-methods
class _RequestLike(Protocol):
    """
    Protocol for googleapiclient request-like objects.
    """
    def execute(self) -> Mapping[str, object]:
        """
        Execute the HTTP request and return JSON response.
        """

class _PaginatedListResource(Protocol):
    """
    Protocol for googleapiclient Resource collection exposing
    list() and list_next() methods.
    """
    def list(self, **kwargs) -> _RequestLike:
        """
        Build a list request for the collection.
        """

    def list_next(
        self,
        prev_request: _RequestLike,
        prev_response: Mapping[str, object]
    ) -> Optional[_RequestLike]:
        """
        Constructs the next page request for the collection.
        """

# pylint: disable=too-many-instance-attributes

EVENTS = {
    'gemini': [
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'calendar': [],
    'chat': [
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'assuredcontrols': [
        'CREATE_APPLICATION_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'commoncontrols': [
        'CREATE_APPLICATION_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'SYSTEM_DEFINED_RULE_UPDATED',
        'TOGGLE_CAA_ENABLEMENT',
        'TOGGLE_SERVICE_ENABLED',
        'ALLOW_SERVICE_FOR_OAUTH2_ACCESS',
        'DISALLOW_SERVICE_FOR_OAUTH2_ACCESS',
        'UNTRUST_DOMAIN_OWNED_OAUTH2_APPS',
        'TRUST_DOMAIN_OWNED_OAUTH2_APPS',
        'BLOCK_ALL_THIRD_PARTY_API_ACCESS',
        'UNBLOCK_ALL_THIRD_PARTY_API_ACCESS',
        'SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS',
        'DELETE_APPLICATION_SETTING'
],
    'drive': [
        'CREATE_APPLICATION_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'CHANGE_DOCS_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'gmail': [
        'CHANGE_GMAIL_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'CHANGE_EMAIL_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'groups': [],
    'meet': [
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'sites': [],
    'classroom': [],
    'all': [None]
}


SELECTORS = ['google', 'selector1', 'selector2']

# All known Google Workspace product/SKU combinations queried by get_license_data().
# Source: https://developers.google.com/workspace/admin/licensing/v1/how-tos/products
KNOWN_SKUS = [
    # Core Google Workspace editions
    {'product_id': 'Google-Apps', 'sku_id': '1010020027', 'name': 'Google Workspace Business Starter'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020028', 'name': 'Google Workspace Business Standard'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020025', 'name': 'Google Workspace Business Plus'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020029', 'name': 'Google Workspace Enterprise Starter'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020026', 'name': 'Google Workspace Enterprise Standard'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020020', 'name': 'Google Workspace Enterprise Plus'},
    {'product_id': 'Google-Apps', 'sku_id': '1010060001', 'name': 'Google Workspace Essentials'},
    {'product_id': 'Google-Apps', 'sku_id': '1010060003', 'name': 'Google Workspace Enterprise Essentials'},
    {'product_id': 'Google-Apps', 'sku_id': '1010060005', 'name': 'Google Workspace Enterprise Essentials Plus'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020030', 'name': 'Google Workspace Frontline Starter'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020031', 'name': 'Google Workspace Frontline Standard'},
    {'product_id': 'Google-Apps', 'sku_id': '1010020034', 'name': 'Google Workspace Frontline Plus'},
    # Gemini add-ons
    {'product_id': '101047', 'sku_id': '1010470001', 'name': 'Gemini Enterprise'},
    {'product_id': '101047', 'sku_id': '1010470002', 'name': 'Gemini Labs'},
    {'product_id': '101047', 'sku_id': '1010470003', 'name': 'Gemini Business'},
    {'product_id': '101047', 'sku_id': '1010470006', 'name': 'Gemini Security'},
    {'product_id': '101047', 'sku_id': '1010470007', 'name': 'Gemini Meet'},
    # Cloud Identity
    {'product_id': '101001', 'sku_id': '1010010001', 'name': 'Cloud Identity Free'},
    {'product_id': '101005', 'sku_id': '1010050001', 'name': 'Cloud Identity Premium'},
    # Assured Controls
    {'product_id': '101039', 'sku_id': '1010390001', 'name': 'Assured Controls'},
    {'product_id': '101039', 'sku_id': '1010390002', 'name': 'Assured Controls Plus'},
    # Google Vault
    {'product_id': 'Google-Vault', 'sku_id': 'Google-Vault', 'name': 'Google Vault'},
    # Google Voice
    {'product_id': '101033', 'sku_id': '1010330003', 'name': 'Google Voice Starter'},
    {'product_id': '101033', 'sku_id': '1010330004', 'name': 'Google Voice Standard'},
    {'product_id': '101033', 'sku_id': '1010330002', 'name': 'Google Voice Premier'},
    # Chrome Enterprise
    {'product_id': '101040', 'sku_id': '1010400001', 'name': 'Chrome Enterprise Premium'},
]

# Privilege names (the values of role.rolePrivileges[*].privilegeName
# returned by directory/v1/roles/list) that indicate a "highly privileged"
# admin role for the purposes of GWS.COMMONCONTROLS.6.  Any custom role
# that contains at least one of these privileges is treated as privileged.
#
# NOTE: the Super Admin role is NOT identified through this set - Google
# represents it with the role-level boolean ``isSuperAdminRole`` instead of
# a privilege.  See _is_privileged_role().
HIGHLY_PRIVILEGED_PRIVILEGES = frozenset({
    'ADMIN_OAUTH_PRIVILEGE_GROUP',  # User Management Admin (legacy alias)
    'ADMIN_ROLE_MANAGEMENT',        # manage admin roles (Services Admin)
    'GROUPS_ALL',                   # Groups Admin
    'MANAGE_USER_LICENSES',
    'MOBILE_ALL',                   # Mobile Admin
    'ORGANIZATION_UNITS_ALL',
    'SERVICES_ALL',                 # Services Admin
    'USERS_ALL',                    # User Management Admin
    'USERS_CREATE',
    'USERS_SECURITY',               # change passwords / 2SV
    'USERS_UPDATE',
})

# Built-in role names that are considered privileged in the baseline text.
# This is used as a fallback for tenants where rolePrivileges values differ
# from expected privilege identifiers.
HIGHLY_PRIVILEGED_ROLE_NAMES = frozenset({
    'SUPER_ADMIN',
    '_SEED_ADMIN_ROLE',
    'USER MANAGEMENT ADMIN',
    'USER MANAGEMENT ADMINISTRATOR',
    'SERVICES ADMIN',
    'MOBILE ADMIN',
    'GROUPS ADMIN',
})

# For DKIM.
# Unfortunately, hard-coded. Ideally, we'd be able to use an API to get
# the selectors used programmatically, but it doesn't seem like there is
# support for that.
# "google" is the default selector Gmail uses,
# "selector1" and "selector2" are commonly used as well,
# but there's nothing to say that agencies have to use these selectors.
# If they were to use a different selector and we don't try the right
# selector, that would result in false positives
#
# We may want to provide a way for admins to input their selectors manually,
# 1. Go to https://admin.google.com/ac/appsettings/740348119625
# 2. Click "Authenticate email"
# 3. Look under "DNS Host name (TXT record name):", the selector will be the
#    beginning of the domain name up to the first period
#


class Provider:
    """
    Class for making the GWS api calls and tracking the results.
    """

    def __init__(self,
                 customer_id: str,
                 credentials_file: Path,
                 *, # everything after this is keyword-only
                 access_token: str = None,
                 svc_account_email: str = None,
                 dns_resolvers: list = None,
                 doh_servers: list = None,
                 skip_doh: bool = False):

        """Initialize the Provider.

        :param customer_id: the ID of the customer to run against.
        :param credentials_file: file specification of Google JSON-format
            credentials.
        :param access_token: (optional) access token string that will be used
            instead of the credentials file.
        :param svc_account_email: (optional) email address for the service
            account.
        :param dns_resolvers: (optional) list of DNS resolvers that should be
            used for DNS queries.
        :param doh_servers: (optional) list of DoH servers that should be used 
            for DoH queries.           
        :param skip_doh: (optional) whether or not failed DNS queries should be
            retried over DoH.
        """

        self._gws_auth = GwsAuth(credentials_file, access_token, svc_account_email)
        self._credentials = self._gws_auth.credentials
        self._services = {}
        self._customer_id = customer_id
        self._successful_calls = set()
        self._unsuccessful_calls = set()
        self._missing_policies = set()
        self._dns_client = RobustDNSClient(dns_resolvers, doh_servers, skip_doh)
        self._domains = []
        self._alias_domains = []

        self._initialize_services()
        self._top_ou = self.get_toplevel_ou()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        for resource in self._services.values():
            resource.close()

    @property
    def successful_calls(self):

        """Returns names of methods successfully called.

        :rtype: set
        """

        return self._successful_calls

    @property
    def unsuccessful_calls(self):

        """Returns names of methods unsuccessfully called.

        :rtype: set
        """

        return self._unsuccessful_calls

    @property
    def missing_policies(self):

        """Returns names of policies missing from the policy API output.

        :rtype: set
        """

        return self._missing_policies

    def _initialize_services(self):

        service_list = (('reports', 'admin', 'reports_v1'),
                        ('directory', 'admin', 'directory_v1'),
                        ('groups', 'groupssettings', 'v1'))

        for service_data in service_list:

            name, service_name, version = service_data

            self._services[name] = build(service_name,
                                         version,
                                         cache_discovery = False,
                                         credentials = self._credentials)

    def _cached_list(
        self,
        attribute: str,
        open_resource: Callable[[], ContextManager[_PaginatedListResource]],
        item_key: str,
        api_reference: ApiReference,
    ) -> list:
        """
        Generic wrapper around the Google list() API.
        Ensures only a single API call is made and caches the results for consecutive API calls.

        :param str attribute: Name of the Provider instance attribute
            used to cache results, e.g. '_domains', '_alias_domains', etc.

        :param Callable open_resource: A callable function that returns a context manager
            for the target Resource collection, e.g. self._services['directory'].domains.
            Only pass the bound method, _cached_list() will invoke the function with
            open_resource()

        :param str item_key: The key used in the API request to extract the list of items,
            e.g. 'domains', 'domainAliases', etc.

        :param ApiReference api_reference: The ApiReference enum value corresponding
            to the API call being made.

        :returns: List of items returned from the target Resource collection.
        """
        if not getattr(self, attribute):
            try:
                with open_resource() as from_resource:
                    data = (from_resource.list(customer = self._customer_id)
                            .execute().get(item_key, []))
                setattr(self, attribute, data)
                self._successful_calls.add(api_reference.value)
            except Exception as exc:
                setattr(self, attribute, [])
                warnings.warn(
                    f'An exception was thrown when calling {api_reference.value}: {exc}',
                    RuntimeWarning
                )
                self._unsuccessful_calls.add(api_reference.value)
        return getattr(self, attribute)

    def list_domains(self) -> list:
        """
        Return the customer's domains. Ensures that the domains API is called only once and that
        the domains used throughout the provider are consistent.
        """
        return self._cached_list(
            attribute = '_domains',
            open_resource = self._services['directory'].domains,
            item_key = 'domains',
            api_reference = ApiReference.LIST_DOMAINS,
        )

    def list_alias_domains(self) -> list:
        """
        Return the customer's alias domains. Ensures that the domain alias API is called only once.
        """
        return self._cached_list(
            attribute = '_alias_domains',
            open_resource = self._services['directory'].domainAliases,
            item_key = 'domainAliases',
            api_reference = ApiReference.LIST_ALIAS_DOMAINS,
        )

    def get_spf_records(self, domains: set) -> list:
        """
        Gets the SPF records for each domain in domains.

        :param domains: The list of domain names (strings).
        """
        results = []
        for domain in domains:
            result = self._dns_client.query(domain)
            results.append({
                'domain': domain,
                'rdata': result['answers'],
                'log': result['log_entries']
            })
        return results

    def get_dkim_records(self, domains: set) -> list:
        """
        Gets the DKIM records for each domain in domains.

        :param domains: The list of domain names (strings).
        """
        results = []
        for domain in domains:
            qnames = [f'{selector}._domainkey.{domain}' for selector in SELECTORS]
            log_entries = []
            for qname in qnames:
                result = self._dns_client.query(qname)
                log_entries.extend(result['log_entries'])
                if len(result['answers']) == 0:
                    # The DKIM record does not exist with this selector, we need to try again with
                    # a different one
                    continue
                # Otherwise, the DKIM record exists with this selector, no need to try the rest
                break

            results.append({
                'domain': domain,
                'rdata': result['answers'],
                'log': log_entries
            })

        return results

    def get_dmarc_records(self, domains: set) -> list:
        """
        Gets the DMARC records for each domain in domains.

        :param domains: The list of domain names (strings).
        """
        results = []
        for domain in domains:
            log_entries = []
            qname = f'_dmarc.{domain}'
            result = self._dns_client.query(qname)
            log_entries.extend(result['log_entries'])
            if len(result['answers']) == 0:
                # The domain does not exist. If the record is not available at the full domain
                # level, we need to check at the organizational domain level.
                labels = domain.split('.')
                org_domain = f'{labels[-2]}.{labels[-1]}'
                result = self._dns_client.query(f'_dmarc.{org_domain}')
                log_entries.extend(result['log_entries'])
            results.append({
                'domain': domain,
                'rdata': result['answers'],
                'log': log_entries
            })
        return results

    def get_dnsinfo(self):
        """
        Gets DNS Information for Gmail baseline
        """
        output = {
            'domains': [],
            'alias_domains': [],
            'spf_records': [],
            'dkim_records': [],
            'dmarc_records': []
        }

        # Get primary/secondary domains
        base_domains = {
            d['domainName']
            for d in self.list_domains() if d.get('verified', True)
        }
        # Get domain aliases
        alias_domains = {
            d['domainAliasName']
            for d in self.list_alias_domains() if d.get('verified', True)
        }
        all_domains = base_domains.union(alias_domains)

        if len(all_domains) == 0:
            log.warning('No domains found, unable to request SPF, DKIM, or DMARC records.')
            return output

        output['domains'].extend(base_domains)
        output["alias_domains"].extend(alias_domains)

        operations = [
            # Only check primary/secondary domains
            ('spf_records', self.get_spf_records, base_domains),
            ('dkim_records', self.get_dkim_records, base_domains),
            # Check primary/secondary domains and alias domains for the DMARC check
            ('dmarc_records', self.get_dmarc_records, all_domains),
        ]

        for key, fnc, domains in operations:
            fnc_name = fnc.__name__
            try:
                output[key] = fnc(domains)
                self._successful_calls.add(fnc_name)
            except Exception as exc:
                output[key] = []
                log.warning('An exception was thrown by %s: %s', fnc_name, str(exc))
                self._unsuccessful_calls.add(fnc_name)

        return output

    def get_super_admins(self) -> dict:
        """
        Gets the org unit/primary email of all super admins, using the directory API
        """

        try:
            with self._services['directory'].users() as users:
                user_list = self._get_list(users,
                                           'users',
                                           customer = self._customer_id,
                                           query = 'isAdmin=True')

            admins = []
            for user in user_list:
                org_unit = user['orgUnitPath']
                # strip out the leading '/'
                org_unit = org_unit[1:] if org_unit.startswith('/') else org_unit
                email = user['primaryEmail']
                admins.append({'primaryEmail': email, 'orgUnitPath': org_unit})
            self._successful_calls.add(ApiReference.LIST_USERS.value)
            return {'super_admins': admins}
        except Exception as exc:
            warnings.warn(
                f'Exception thrown while getting super admins; outputs will be incorrect: {exc}',
                RuntimeWarning
            )
            self._unsuccessful_calls.add(ApiReference.LIST_USERS.value)
            return {'super_admins': []}

    def get_privileged_users(self) -> dict:
        """
        Gets all "highly privileged" users (per GWS.COMMONCONTROLS.6 -
        cisagov/ScubaGoggles#589).  A user is considered privileged if any
        of the following are true:

          1. They are a Super Admin (``user.isAdmin == True``).
          2. They hold an assignment to the built-in Super Admin role
             (``role.isSuperAdminRole == True``).
          3. They hold an assignment to any role whose ``rolePrivileges``
             contains at least one privilege from
             ``HIGHLY_PRIVILEGED_PRIVILEGES`` (covers the User Management,
             Services, Mobile, and Groups admin roles, plus any custom
             role that grants the same privileges).

        Returns a dictionary with two keys:
          - ``privileged_users``: list of dictionaries, each with
            ``primaryEmail``, ``orgUnitPath``, and ``groupKeys`` (group ids
            and email addresses for groups the user is a direct member of).
          - ``privileged_users_error``: ``None`` on success, otherwise a
            string describing the failure.
        """

        api_calls = (ApiReference.LIST_ROLES.value,
                     ApiReference.LIST_ROLE_ASSIGNMENTS.value,
                     ApiReference.LIST_USERS.value)

        try:
            users = self._list_directory_users()
            privileged_user_ids = self._collect_privileged_user_ids(users)
            privileged_users = self._build_privileged_user_records(
                users, privileged_user_ids)

            for call in api_calls:
                self._successful_calls.add(call)
            return {'privileged_users': privileged_users,
                    'privileged_users_error': None}
        except Exception as exc:
            warnings.warn(
                'Exception thrown while getting privileged users; '
                f'GWS.COMMONCONTROLS.6.1 cannot be evaluated: {exc}',
                RuntimeWarning
            )
            for call in api_calls:
                self._unsuccessful_calls.add(call)
            return {'privileged_users': [],
                    'privileged_users_error': str(exc)}

    def get_inbound_sso_assignments(self) -> dict:
        """
        Gets Cloud Identity Inbound SSO assignments for the customer.

        Returns:
          - inbound_sso_assignments: list of assignment objects as returned by
            Cloud Identity's inboundSsoAssignments.list endpoint.
          - inbound_sso_assignments_error: None on success, otherwise the
            error message string.
        """
        api_call = ApiReference.LIST_INBOUND_SSO_ASSIGNMENTS.value
        base_url = 'https://cloudidentity.googleapis.com/v1/inboundSsoAssignments'
        session = None

        try:
            customer_parent = self._get_cloud_identity_customer_parent()
            params = {
                'filter': f'customer==\"{customer_parent}\"',
                'pageSize': 100  # API max pageSize for this endpoint
            }
            session = auth_requests.AuthorizedSession(self._credentials)
            assignments = []
            while True:
                response = session.get(base_url, params=params, timeout=30)
                response.raise_for_status()
                payload = response.json()
                assignments.extend(payload.get('inboundSsoAssignments', []))
                page_token = payload.get('nextPageToken', '')
                if not page_token:
                    break
                params['pageToken'] = page_token

            self._successful_calls.add(api_call)
            return {'inbound_sso_assignments': assignments,
                    'inbound_sso_assignments_error': None}
        except Exception as exc:
            warnings.warn(
                'Exception thrown while getting inbound SSO assignments; '
                f'GWS.COMMONCONTROLS.6.1 cannot be evaluated: {exc}',
                RuntimeWarning
            )
            self._unsuccessful_calls.add(api_call)
            return {'inbound_sso_assignments': [],
                    'inbound_sso_assignments_error': str(exc)}
        finally:
            if session is not None:
                session.close()

    def _get_cloud_identity_customer_parent(self) -> str:
        """
        Returns the Cloud Identity API parent string for the current tenant.

        Cloud Identity endpoints require `customers/{customer-id}` where
        customer-id is the canonical ID (e.g. `C0123abc`).  Unlike Directory
        APIs, aliases like `my_customer` are not accepted.
        """
        if self._customer_id != 'my_customer':
            return f'customers/{self._customer_id}'

        # Resolve alias -> canonical customer id using Directory API.
        response = self._services['directory'].customers().get(
            customerKey=self._customer_id
        ).execute()
        customer_id = response.get('id', '').strip()
        if not customer_id:
            raise RuntimeError('Unable to resolve canonical customer id for Cloud Identity API')
        return f'customers/{customer_id}'

    def _collect_privileged_user_ids(self, users: list) -> set:
        """Helper: Returns the union of:
          - user ids of Super Admins (``isAdmin`` flag)
          - user ids assigned a privileged role (Super Admin role or any
            role whose privileges include a HIGHLY_PRIVILEGED_PRIVILEGES
            entry)

        Raises any exception from the underlying Directory API calls."""

        super_admin_ids = {u['id'] for u in users
                           if u.get('isAdmin') and u.get('id')}
        delegated_admin_ids = {u['id'] for u in users
                               if u.get('isDelegatedAdmin') and u.get('id')}

        directory = self._services['directory']
        with directory.roles() as roles:
            role_list = self._get_list(roles, 'items',
                                       customer = self._customer_id)
        privileged_role_ids = {role['roleId'] for role in role_list
                               if self._is_privileged_role(role)}

        with directory.roleAssignments() as assignments:
            assignment_list = self._get_list(assignments, 'items',
                                             customer = self._customer_id)
        role_assigned_ids = {
            a['assignedTo']
            for a in assignment_list
            if a.get('assigneeType', 'USER') == 'USER'
            and a.get('roleId') in privileged_role_ids
        }

        # In some tenants, roles.list may not return enough metadata to map
        # delegated admin assignments to privilege identifiers reliably.  As a
        # safety fallback, include all delegated admins from the users feed.
        return super_admin_ids | role_assigned_ids | delegated_admin_ids

    @staticmethod
    def _is_privileged_role(role: dict) -> bool:
        """Helper: True if the given Directory role is highly privileged
        (the Super Admin role, or any role granting one of the watched
        privileges)."""

        if role.get('isSuperAdminRole', False):
            return True
        role_name = str(role.get('roleName', '')).upper()
        if role_name in HIGHLY_PRIVILEGED_ROLE_NAMES:
            return True
        privilege_names = {p.get('privilegeName')
                           for p in role.get('rolePrivileges', ())}
        return bool(privilege_names & HIGHLY_PRIVILEGED_PRIVILEGES)

    def _list_directory_users(self) -> list:
        """Helper: lists all directory users for the configured customer."""

        with self._services['directory'].users() as users:
            return self._get_list(users, 'users',
                                  customer = self._customer_id)

    def _build_privileged_user_records(self, users: list,
                                       privileged_user_ids: set) -> list:
        """Helper: builds the list of {primaryEmail, orgUnitPath} dicts for
        the privileged users among the supplied directory users."""

        records = []
        seen = set()
        for user in users:
            if user.get('id') not in privileged_user_ids:
                continue
            email = user.get('primaryEmail', '')
            if email in seen:
                continue
            seen.add(email)
            org_unit = user.get('orgUnitPath', '')
            if org_unit.startswith('/'):
                org_unit = org_unit[1:]
            group_keys = self._list_group_keys_for_user(email)
            records.append({'primaryEmail': email,
                            'orgUnitPath': org_unit,
                            'groupKeys': group_keys})
        return records

    def _list_group_keys_for_user(self, user_email: str) -> list:
        """
        Helper: returns normalized group keys for a user.

        Keys include both the group id and group email (lowercased), so
        policy evaluation can match inbound SSO targetGroup values that use
        either identifier.
        """
        if not user_email:
            return []

        directory = self._services['directory']
        group_keys = set()
        with directory.groups() as groups:
            group_list = self._get_list(groups,
                                        'groups',
                                        userKey = user_email)
        for group in group_list:
            group_id = str(group.get('id', '')).strip().lower()
            group_email = str(group.get('email', '')).strip().lower()
            if group_id:
                group_keys.add(group_id)
            if group_email:
                group_keys.add(group_email)
        return sorted(group_keys)

    def get_ous(self) -> dict:
        """
        Gets the organizational units using the directory API
        """

        try:
            with self._services['directory'].orgunits() as orgunits:
                response = orgunits.list(customerId=self._customer_id,
                                         type='allIncludingParent').execute()
            self._successful_calls.add(ApiReference.LIST_OUS.value)
            if 'organizationUnits' not in response:
                return {}
            return response
        except Exception as exc:
            warnings.warn(
                f'Exception thrown while getting top level OU: {exc}',
                RuntimeWarning
            )
            self._unsuccessful_calls.add(ApiReference.LIST_OUS.value)
            return {}

    def get_toplevel_ou(self) -> str:
        """
        Gets the tenant name using the directory API
        """

        try:
            with self._services['directory'].orgunits() as orgunits:
                response = orgunits.list(customerId = self._customer_id,
                                         orgUnitPath = '/',
                                         type = 'allIncludingParent').execute()

        except RefreshError as exc:
            self._check_scopes(exc)

        except Exception as exc:
            warnings.warn(
                f'Exception thrown while getting top level OU: {exc}',
                RuntimeWarning
            )
            self._check_scopes(exc)
            self._unsuccessful_calls.add(ApiReference.LIST_OUS.value)
            return 'Error Retrieving'

        self._successful_calls.add(ApiReference.LIST_OUS.value)

        for ou in response['organizationUnits']:
            if ou['orgUnitPath'] == '/':
                return ou['name']

        log.warning('Unable to determine the name of the top-level OU.')
        return ''

    def get_tenant_info(self) -> dict:
        """
        Gets the high-level tenant info using the directory API
        """
        tenant_id = ''
        try:
            response = self._services['directory'].customers().get(
                            customerKey = self._customer_id).execute()
            tenant_id = response.get('id')
            primary_domain = 'Error Retrieving'
            for domain in self.list_domains():
                if domain['isPrimary']:
                    primary_domain = domain['domainName']
                    break
            return {
                'ID' : tenant_id,
                'domain': primary_domain,
                'topLevelOU': self._top_ou
            }
        except Exception as exc:
            warnings.warn(
                f'Exception thrown while retrieving customer list: {exc}',
                RuntimeWarning
            )
            self._unsuccessful_calls.add(ApiReference.LIST_CUSTOMERS.value)
            return {
                'ID': "",
                'domain': primary_domain,
                'topLevelOU': self._top_ou
        }

    def get_gws_logs(self, products: list, event: str) -> dict:
        """
        Gets the GWS admin audit logs with the specified event name.
        This function will also some parsing and filtering to ensure that an appropriate
        log event is matched to the appropriate product.
        This is to prevent the same log event from being duplicated
        across products in the resulting provider JSON.

        :param products: a narrowed list of the products being invoked
        authenticating in auth.py
        :param event: the name of the specific event we are querying for.
        """

        with self._services['reports'].activities() as activities:
            reports = self._get_list(activities,
                                     'items',
                                     userKey = 'all',
                                     applicationName = 'admin',
                                     eventName = event)

        # Used for filtering duplicate events
        prod_to_app_name_values = {
            'calendar': ['Calendar'],
            'chat': ['Google Chat', 'Google Workspace Marketplace'],
            'assuredcontrols': ['Access Approvals', "Data regions"],
            'commoncontrols': [
                'Security',
                'Google Workspace Marketplace',
                'Blogger',
                'Google Books',
                'Google Maps',
                'Google Pay',
                'Google Photos',
                'Google Play',
                'Google Play Console',
                'Timeline - Location History',
                'YouTube',
                'Google Cloud Platform Sharing Options',
                'Multi Party Approval',
                'Data regions'
            ],
            'drive': ['Drive and Docs'],
            'gmail': ['Gmail'],
            'gemini': ['Gemini app', 'Gemini in Workspace apps'],
            'groups': ['Groups for Business'],
            'meet': ['Google Meet', 'Google Meet GenAI'],
            'sites': ['Sites'],
            'classroom': ['Classroom']
        }
        # create a subset of just the products we need from the dict above
        subset_prod_to_app_name = {
            prod: prod_to_app_name_values[prod]
            for prod in products if prod in prod_to_app_name_values
        }

        products_to_logs = create_key_to_list(products)
        # Certain events are not being currently being filtered because
        # filtering for those events here would be duplicative of the Rego code
        try:
            # the value we want is nested several layers deep
            # checks under the APPLICATION_NAME key for the correct app_name value
            dup_events = (
                'CHANGE_APPLICATION_SETTING',
                'CREATE_APPLICATION_SETTING',
                'DELETE_APPLICATION_SETTING'
                )
            if event in dup_events:
                app_name = 'APPLICATION_NAME'
                for report in reports:
                    for events in report['events']:
                        parameters = events.get('parameters', [])
                        for parameter in parameters:
                            if parameter.get('name') == app_name:
                                param_val = parameter.get('value')
                                for prod, app_values in subset_prod_to_app_name.items():
                                    if param_val in app_values:
                                        products_to_logs[prod].append(report)
            else:
                # no filtering append entire response to relevant product
                for prod in products:
                    products_to_logs[prod].extend(reports)
        except Exception as exc:
            warnings.warn(
                f'An exception was thrown while getting the logs; outputs will be incorrect: {exc}',
                RuntimeWarning
            )
        return products_to_logs

    def get_group_settings(self) -> dict:
        """
        Gets all of the group info using the directory API and group settings API
        """

        group_service = self._services['groups']
        directory_service = self._services['directory']

        try:
            # get the group settings for each groups
            group_settings = []

            with (directory_service.groups() as ds_groups,
                  group_service.groups() as gs_groups):
                group_list = self._get_list(ds_groups, 'groups', customer = self._customer_id)
                group_settings = [gs_groups.get(groupUniqueId = group['email'])
                                  .execute() for group in group_list]

            self._successful_calls.add(ApiReference.LIST_GROUPS.value)
            self._successful_calls.add(ApiReference.GET_GROUP.value)
            return {'group_settings': group_settings}
        except Exception as exc:
            warnings.warn(
                f'Exception thrown while getting group settings; outputs will be incorrect: {exc}',
                RuntimeWarning
            )
            self._unsuccessful_calls.add(ApiReference.LIST_GROUPS.value)
            self._unsuccessful_calls.add(ApiReference.GET_GROUP.value)
            return {'group_settings': []}

    def get_license_data(self) -> dict:
        """
        Gets license assignment counts for each known Google Workspace SKU
        using the Enterprise License Manager API (free, no reseller access required).

        Scope required: https://www.googleapis.com/auth/apps.licensing

        Returns a dict with key 'license_data' containing a list of subscription
        records, one per active SKU (i.e., SKUs with at least one assigned user).
        Each record has: product_name, sku_id, product_id, status, assigned.

        Note: Total seat counts and expiration dates are only available via the
        Google Reseller API and are not included here.
        """
        api_call = ApiReference.LIST_LICENSE_ASSIGNMENTS.value
        subscriptions = []

        primary_domain = None
        for domain in self.list_domains():
            if domain.get('isPrimary'):
                primary_domain = domain['domainName']
                break
        if not primary_domain:
            primary_domain = self._customer_id

        try:
            licensing_service = build('licensing', 'v1',
                                      cache_discovery=False,
                                      credentials=self._credentials)

            any_success = False
            for sku in KNOWN_SKUS:
                try:
                    count = 0
                    page_token = None
                    while True:
                        kwargs = {
                            'productId': sku['product_id'],
                            'skuId': sku['sku_id'],
                            'customerId': primary_domain,
                            'maxResults': 1000,
                        }
                        if page_token:
                            kwargs['pageToken'] = page_token
                        response = (licensing_service
                                    .licenseAssignments()
                                    .listForProductAndSku(**kwargs)
                                    .execute())
                        count += len(response.get('items', []))
                        page_token = response.get('nextPageToken')
                        if not page_token:
                            break

                    any_success = True
                    if count > 0:
                        subscriptions.append({
                            'product_name': sku['name'],
                            'sku_id': sku['sku_id'],
                            'product_id': sku['product_id'],
                            'status': 'Active',
                            'assigned': count,
                        })
                except Exception:
                    pass

            if any_success:
                self._successful_calls.add(api_call)
            else:
                self._unsuccessful_calls.add(api_call)

        except Exception as exc:
            warnings.warn(
                f'Exception thrown while getting license data; '
                f'subscription table will be omitted: {exc}',
                RuntimeWarning
            )
            self._unsuccessful_calls.add(api_call)

        return {'license_data': subscriptions}

    def call_gws_providers(self, products: list, quiet) -> dict:
        """
        Calls the relevant GWS APIs to get the data we need for the baselines.
        Data such as the admin audit log, super admin users etc.

        :param products: list of product names to check
        :param quiet: suppress tqdm output
        """
        # create a inverse dictionary containing a mapping of event => list of products
        events_to_products = create_subset_inverted_dict(EVENTS, products)
        events_to_products_bar = tqdm(events_to_products.items(),
                                      leave = False,
                                      disable = quiet)

        # main aggregator dict
        product_to_logs = create_key_to_list(products)
        product_to_items = {}
        ou_ids = set()
        ou_ids.add('') # certain settings have no OU
        try:
            # Add top level organization unit name
            ou_ids.add(self._top_ou)
            # get all organizational unit data
            product_to_items['organizational_units'] = self.get_ous()
            orgunits = product_to_items['organizational_units']
            sub_orgunits = orgunits.get('organizationUnits', ())

            for orgunit in sub_orgunits:
                ou_ids.add(orgunit['name'])
            # add just organizational unit names to a field]
            product_to_items['organizational_unit_names'] = list(ou_ids)
        except Exception as exc:
            warnings.warn(
                f'Exception thrown while getting tenant data: {exc}',
                RuntimeWarning
            )

        # call the api once per event type
        try:
            for event, product_list in events_to_products_bar:
                products = ', '.join(product_list)
                bar_descr = f'Running Provider: Exporting {event} events for {products}...'
                events_to_products_bar.set_description(bar_descr)

                # gets the GWS admin audit logs and merges them into product_to_logs
                # aggregator dict
                product_to_logs = merge_dicts(
                    product_to_logs,
                    self.get_gws_logs(products = product_list, event = event)
                )
                self._successful_calls.add(ApiReference.LIST_ACTIVITIES.value)
        except Exception as exc:
            warnings.warn('Provider Exception thrown while getting the logs; '
                f'outputs will be incorrect: {exc}', RuntimeWarning)
            self._unsuccessful_calls.add(ApiReference.LIST_ACTIVITIES.value)

        with PolicyAPI(self._gws_auth, self._top_ou) as policy_api:
            policies = policy_api.get_policies()
            self._missing_policies = policy_api.verify(policies)

        product_to_items['policies'] = policies

        # repacks the main aggregator into the original form
        # that the api returns the data in; under an 'items' key.
        # Then we put this key under a {product}_log key for the Rego code
        try:
            for product, logs in product_to_logs.items():
                key_name = f'{product}_logs'
                product_to_items[key_name] = {'items': logs}

            # get tenant metadata for report front page header
            product_to_items['tenant_info'] = self.get_tenant_info()

            if 'gmail' in product_to_logs:
                # add dns info if gmail is being run
                product_to_items.update(self.get_dnsinfo())

            if 'commoncontrols' in product_to_logs:
                # add list of super admins if CC is being run
                product_to_items.update(self.get_super_admins())
                # add list of highly privileged users (CC 6.1)
                product_to_items.update(self.get_privileged_users())
                # add effective SSO assignment state (CC 6.1 API-based check)
                product_to_items.update(self.get_inbound_sso_assignments())
                # add license/subscription data for common controls report
                product_to_items.update(self.get_license_data())

            product_to_items.update(self.get_group_settings())

        except Exception as exc:
            warnings.warn(
                f'Uncaught Exception thrown while getting other data: {exc}',
                RuntimeWarning
            )

        product_to_items['successful_calls'] = list(self._successful_calls)
        product_to_items['unsuccessful_calls'] = list(self._unsuccessful_calls)
        product_to_items['missing_policies'] = list(self._missing_policies)

        return product_to_items

    @staticmethod
    def _get_list(resource, item: str, **list_args) -> list:

        """Given a Google Resource and the name of an item to retrieve, with
        possible criteria, this helper method returns a list of results.

        The given Resource object must have both list() and list_next()
        methods because the intention of this method is to handle the case
        where the result is too large for Google to return in a single
        request.

        :param Resource resource: a Google resource instance.

        :param str item: the name of the item to retrieve from the results.
            This is a key in the returned dictionary.

        :param list_args: optional, keyword/value arguments to be passed
            to the list() method.

        :return: list of requested items.
        """

        results = []
        request = resource.list(**list_args)

        while request is not None:
            response = request.execute()
            results += response.get(item, [])
            # If all the results have been returned, list_next() will return
            # None.
            request = resource.list_next(request, response)

        return results

    def _check_scopes(self, exc: Exception):
        # If one of the scopes is not authorized in a Service account the
        # error is thrown: ('access_denied: Requested client not authorized.',
        # {'error': 'access_denied', 'error_description': 'Requested client not authorized.'})
        scopes_list = self._credentials.scopes
        if 'access_denied: Requested client not authorized.' in str(exc):
            log.error('Your credential may be missing one'
                      ' of the following scopes: %s', scopes_list)
        raise exc
