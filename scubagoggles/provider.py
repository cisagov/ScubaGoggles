"""
provider.py is where the GWS api calls are made.
"""

import logging
import warnings
from pathlib import Path
from tqdm import tqdm

from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError
from scubagoggles.auth import GwsAuth
from scubagoggles.policy_api import PolicyAPI
from scubagoggles.utils import create_subset_inverted_dict, \
    create_key_to_list, merge_dicts
from scubagoggles.scuba_constants import ApiReference
from scubagoggles.robust_dns import RobustDNSClient

log = logging.getLogger(__name__)

# pylint: disable=too-many-instance-attributes

EVENTS = {
    'calendar': [],
    'chat': [
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'commoncontrols': [
        'CREATE_APPLICATION_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'SYSTEM_DEFINED_RULE_UPDATED',
        'TOGGLE_CAA_ENABLEMENT',
        'TOGGLE_SERVICE_ENABLED',
        'CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS',
        'ALLOW_SERVICE_FOR_OAUTH2_ACCESS',
        'DISALLOW_SERVICE_FOR_OAUTH2_ACCESS',
        'UNTRUST_DOMAIN_OWNED_OAUTH2_APPS',
        'TRUST_DOMAIN_OWNED_OAUTH2_APPS',
        'BLOCK_ALL_THIRD_PARTY_API_ACCESS',
        'UNBLOCK_ALL_THIRD_PARTY_API_ACCESS',
        'SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS',
        'DELETE_APPLICATION_SETTING',
        'CHANGE_DATA_LOCALIZATION_FOR_RUSSIA'
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
                 svc_account_email: str = None):

        """Initialize the Provider.

        :param customer_id: the ID of the customer to run against.
        :param credentials_file: file specification of Google JSON-format
            credentials.
        :param svc_account_email: (optional) email address for the service
            account.
        """

        self._gws_auth = GwsAuth(credentials_file, svc_account_email)
        self._credentials = self._gws_auth.credentials
        self._services = {}
        self._customer_id = customer_id
        self._successful_calls = set()
        self._unsuccessful_calls = set()
        self._missing_policies = set()
        self._dns_client = RobustDNSClient()
        self._domains = None

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

    def list_domains(self) -> list:
        """
        Return the customer's domains. Ensures that the domains API is called only once and that
        the domains used throughout the provider are consistent.
        """
        if self._domains is None:
            try:
                with self._services['directory'].domains() as domains:
                    self._domains = (domains.list(customer = self._customer_id)
                                     .execute()['domains'])
                self._successful_calls.add(ApiReference.LIST_DOMAINS.value)
            except Exception as exc:
                self._domains = []
                warnings.warn(f'An exception was thrown by list_domains: {exc}', RuntimeWarning)
                self._unsuccessful_calls.add(ApiReference.LIST_DOMAINS.value)
        return self._domains

    def get_spf_records(self, domains: set) -> list:
        """
        Gets the SPF records for each domain in domains.

        :param domains: The list of domain names (strings).
        """
        results = []
        n_low_confidence = 0
        for domain in domains:
            result = self._dns_client.query(domain)
            if not result['HighConfidence']:
                n_low_confidence += 1
            results.append({
                'domain': domain,
                'rdata': result['Answers'],
                'log': result['LogEntries']
            })
        if n_low_confidence > 0:
            warnings.warn(f"get_spf_records: for {n_low_confidence} domain(s), \
    the traditional DNS queries returned an empty answer \
    section and the DoH queries failed. Will assume SPF not configured, but \
    can't guarantee that failure isn't due to something like split horizon DNS. \
    See ProviderSettingsExport.json under 'spf_records' for more details.", RuntimeWarning)
        return results

    def get_dkim_records(self, domains: set) -> list:
        """
        Gets the DKIM records for each domain in domains.

        :param domains: The list of domain names (strings).
        """
        results = []
        n_low_confidence = 0
        for domain in domains:
            qnames = [f'{selector}._domainkey.{domain}' for selector in SELECTORS]
            log_entries = []
            for qname in qnames:
                result = self._dns_client.query(qname)
                log_entries.extend(result['LogEntries'])
                if len(result['Answers']) == 0:
                    # The DKIM record does not exist with this selector, we need to try again with
                    # a different one
                    continue
                # Otherwise, the DKIM record exists with this selector, no need to try the rest
                break

            if not result['HighConfidence']:
                n_low_confidence += 1
            results.append({
                'domain': domain,
                'rdata': result['Answers'],
                'log': log_entries
            })

        if n_low_confidence > 0:
            warnings.warn(f"get_dkim_records: for {n_low_confidence} domain(s), \
    the traditional DNS queries returned an empty answer \
    section and the DoH queries failed. Will assume DKIM not configured, but \
    can't guarantee that failure isn't due to something like split horizon DNS. \
    See ProviderSettingsExport.json under 'dkim_records' for more details.", RuntimeWarning)
        return results

    def get_dmarc_records(self, domains: set) -> list:
        """
        Gets the DMARC records for each domain in domains.

        :param domains: The list of domain names (strings).
        """
        results = []
        n_low_confidence = 0
        for domain in domains:
            log_entries = []
            qname = f'_dmarc.{domain}'
            result = self._dns_client.query(qname)
            log_entries.extend(result['LogEntries'])
            if len(result['Answers']) == 0:
                # The domain does not exist. If the record is not available at the full domain
                # level, we need to check at the organizational domain level.
                labels = domain.split('.')
                org_domain = f'{labels[-2]}.{labels[-1]}'
                result = self._dns_client.query(f'_dmarc.{org_domain}')
                log_entries.extend(result['LogEntries'])
            if not result['HighConfidence']:
                n_low_confidence += 1
            results.append({
                'domain': domain,
                'rdata': result['Answers'],
                'log': log_entries
            })
        if n_low_confidence > 0:
            warnings.warn(f"get_dmarc_records: for {n_low_confidence} domain(s), \
    the traditional DNS queries returned an empty answer \
    section and the DoH queries failed. Will assume DMARC not configured, but \
    can't guarantee that failure isn't due to something like split horizon DNS. \
    See ProviderSettingsExport.json under 'dmarc_records' for more details.", RuntimeWarning)
        return results

    def get_dnsinfo(self):
        """
        Gets DNS Information for Gmail baseline
        """
        output = {'domains': [], 'spf_records': [], 'dkim_records': [], 'dmarc_records': []}
        domains = {d['domainName'] for d in self.list_domains()}
        if len(domains) == 0:
            warnings.warn('No domains found.', RuntimeWarning)
            return output

        output['domains'].extend(domains)

        try:
            output['spf_records'] = self.get_spf_records(domains)
            self._successful_calls.add('get_spf_records')
        except Exception as exc:
            output['spf_records'] = []
            warnings.warn(f'An exception was thrown by get_spf_records: {exc}', RuntimeWarning)
            self._unsuccessful_calls.add('get_spf_records')
        try:
            output['dkim_records'] = self.get_dkim_records(domains)
            self._successful_calls.add('get_dkim_records')
        except Exception as exc:
            output['dkim_records'] = []
            warnings.warn(f'An exception was thrown by get_dkim_records: {exc}', RuntimeWarning)
            self._unsuccessful_calls.add('get_dkim_records')
        try:
            output['dmarc_records'] = self.get_dmarc_records(domains)
            self._successful_calls.add('get_dmarc_records')
        except Exception as exc:
            output['dmarc_records'] = []
            warnings.warn(f'An exception was thrown by get_dmarc_records: {exc}', RuntimeWarning)
            self._unsuccessful_calls.add('get_dmarc_records')
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

    def get_ous(self) -> dict:
        """
        Gets the organizational units using the directory API
        """

        try:
            with self._services['directory'].orgunits() as orgunits:
                response = orgunits.list(customerId=self._customer_id).execute()
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
            'groups': ['Groups for Business'],
            'meet': ['Google Meet'],
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
        domains = {d['domainName'] for d in self.list_domains() if d['verified']}

        try:
            # get the group settings for each groups
            group_settings = []

            with (directory_service.groups() as ds_groups,
                  group_service.groups() as gs_groups):
                for domain in domains:
                    group_list = self._get_list(ds_groups,
                                                'groups',
                                                domain = domain)

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

            if 'groups' in product_to_logs:
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
