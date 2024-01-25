"""
provider.py is where the GWS api calls are made.

"""
import warnings
from tqdm import tqdm

from scubagoggles.utils import create_subset_inverted_dict, create_key_to_list, merge_dicts
from scubagoggles.robust_dns import RobustDNSClient

EVENTS = {
    'calendar': [
        'CHANGE_CALENDAR_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING'
    ],
    'chat': [
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'commoncontrols': [
        'CREATE_APPLICATION_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'TOGGLE_CAA_ENABLEMENT',
        'WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED',
        'CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS',
        'ENFORCE_STRONG_AUTHENTICATION',
        'ALLOW_SERVICE_FOR_OAUTH2_ACCESS',
        'DISALLOW_SERVICE_FOR_OAUTH2_ACCESS',
        'UNTRUST_DOMAIN_OWNED_OAUTH2_APPS',
        'TRUST_DOMAIN_OWNED_OAUTH2_APPS',
        'BLOCK_ALL_THIRD_PARTY_API_ACCESS',
        'UNBLOCK_ALL_THIRD_PARTY_API_ACCESS',
        'SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS',
        'CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION',
        'CHANGE_TWO_STEP_VERIFICATION_FREQUENCY',
        'DELETE_APPLICATION_SETTING',
        'CHANGE_DATA_LOCALIZATION_FOR_RUSSIA'
    ],
    'drive': [
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
    'groups': ['CHANGE_APPLICATION_SETTING'],
    'meet': [
        'CHANGE_APPLICATION_SETTING',
        'CREATE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'rules': ['SYSTEM_DEFINED_RULE_UPDATED'],
    'sites': ['TOGGLE_SERVICE_ENABLED'],
    'classroom': [
        'CREATE_APPLICATION_SETTING',
        'CHANGE_APPLICATION_SETTING',
        'DELETE_APPLICATION_SETTING'
    ],
    'all': [None]
}

selectors = ["google", "selector1", "selector2"]
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

DNSClient = RobustDNSClient()

def get_spf_records(domains: list) -> list:
    '''
    Gets the SPF records for each domain in domains.

    :param domains: The list of domain names (strings).
    '''
    results = []
    n_low_confidence = 0
    for domain in domains:
        result = DNSClient.query(domain)
        if not result['HighConfidence']:
            n_low_confidence += 1
        results.append({
            "domain": domain,
            "rdata": result["Answers"],
            "log": result["LogEntries"]
        })
    if n_low_confidence > 0:
        warnings.warn(f"get_spf_records: for {n_low_confidence} domain(s), \
the traditional DNS queries returned an empty answer \
section and the DoH queries failed. Will assume SPF not configured, but \
can't guarantee that failure isn't due to something like split horizon DNS. \
See ProviderSettingsExport.json under 'spf_records' for more details.", RuntimeWarning)
    return results

def get_dkim_records(domains : list) -> list:
    '''
    Gets the DKIM records for each domain in domains.

    :param domains: The list of domain names (strings).
    '''
    results = []
    n_low_confidence = 0
    for domain in domains:
        qnames = [f"{selector}._domainkey.{domain}" for selector in selectors]
        log_entries = []
        for qname in qnames:
            result = DNSClient.query(qname)
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
            "domain": domain,
            "rdata": result["Answers"],
            "log": log_entries
        })

    if n_low_confidence > 0:
        warnings.warn(f"get_dkim_records: for {n_low_confidence} domain(s), \
the traditional DNS queries returned an empty answer \
section and the DoH queries failed. Will assume DKIM not configured, but \
can't guarantee that failure isn't due to something like split horizon DNS. \
See ProviderSettingsExport.json under 'dkim_records' for more details.", RuntimeWarning)
    return results

def get_dmarc_records(domains : list) -> list:
    '''
    Gets the DMARC records for each domain in domains.

    :param domains: The list of domain names (strings).
    '''
    results = []
    n_low_confidence = 0
    for domain in domains:
        log_entries = []
        qname = f"_dmarc.{domain}"
        result = DNSClient.query(qname)
        log_entries.extend(result['LogEntries'])
        if len(result["Answers"]) == 0:
            # The domain does not exist. If the record is not available at the full domain
            # level, we need to check at the organizational domain level.
            labels = domain.split(".")
            org_domain = f"{labels[-2]}.{labels[-1]}"
            result = DNSClient.query(f"_dmarc.{org_domain}")
            log_entries.extend(result['LogEntries'])
        if not result['HighConfidence']:
            n_low_confidence += 1
        results.append({
            "domain": domain,
            "rdata": result["Answers"],
            "log": log_entries
        })
    if n_low_confidence > 0:
        warnings.warn(f"get_dmarc_records: for {n_low_confidence} domain(s), \
the traditional DNS queries returned an empty answer \
section and the DoH queries failed. Will assume DMARC not configured, but \
can't guarantee that failure isn't due to something like split horizon DNS. \
See ProviderSettingsExport.json under 'dmarc_records' for more details.", RuntimeWarning)
    return results

def get_dnsinfo(service):
    '''
    Gets DNS Information for Gmail baseline

    :param service: a directory_v1 service instance
    '''
    output = {"domains": [], "spf_records": [], "dkim_records": [], "dmarc_records": []}

    # Determine the tenant's domains via the API
    response = service.domains().list(customer="my_customer").execute()
    domains = {d['domainName'] for d in response['domains']}

    if len(domains) == 0:
        warnings.warn("No domains found.", RuntimeWarning)
        return output

    output["domains"].extend(domains)

    try:
        output["spf_records"] = get_spf_records(domains)
    except Exception as exc:
        output["spf_records"] = []
        warnings.warn(f"An exception was thrown by get_spf_records: {exc}", RuntimeWarning)
    try:
        output["dkim_records"] = get_dkim_records(domains)
    except Exception as exc:
        output["dkim_records"] = []
        warnings.warn(f"An exception was thrown by get_dkim_records: {exc}", RuntimeWarning)
    try:
        output["dmarc_records"] = get_dmarc_records(domains)
    except Exception as exc:
        output["dmarc_records"] = []
        warnings.warn(f"An exception was thrown by get_dmarc_records: {exc}", RuntimeWarning)
    return output

def get_super_admins(service) -> dict:
    '''
    Gets the org unit/primary email of all super admins, using the directory API

    :param service: a directory_v1 service instance
    '''
    try:
        response = service.users().list(customer="my_customer", query="isAdmin=True").execute()
        admins = []
        for user in response['users']:
            org_unit = user['orgUnitPath']
            # strip out the leading '/'
            org_unit = org_unit[1:] if org_unit.startswith('/') else org_unit
            email = user['primaryEmail']
            admins.append({'primaryEmail': email, 'orgUnitPath': org_unit})
        return {'super_admins': admins}
    except Exception as exc:
        warnings.warn(
            f"Exception thrown while getting super admins; outputs will be incorrect: {exc}",
            RuntimeWarning
        )
        return {'super_admins': []}

def get_ous(service) -> dict:
    '''
    Gets the organizational units using the directory API

    :param service: a directory_v1 service instance
    '''

    try:
        response = service.orgunits().list(customerId='my_customer').execute()
        if 'organizationUnits' not in response:
            return {}
        return response
    except Exception as exc:
        warnings.warn(
            f"Exception thrown while getting top level OU: {exc}",
            RuntimeWarning
        )
        return {}

def get_toplevel_ou(service) -> str:
    '''
    Gets the tenant name using the directory API

    :param service: a directory_v1 service instance
    '''

    try:
        response = service.orgunits().list(customerId='my_customer',
                                    orgUnitPath='/',
                                    type='children').execute()
        # Because we set orgUnitPath to / and type to children, the API call will only
        # return the second-level OUs, meaning the parentOrgUnitId of any of the OUs returned
        # will point us to OU of the entire organization
        if 'organizationUnits' not in response:
            # No custom OUs have been created. In this case, we can't
            # determine the name of the top-level OU. See:
            # https://stackoverflow.com/questions/26936357/google-directory-api-org-name-of-root-org-unit-path
            # https://stackoverflow.com/questions/60464432/cannot-get-root-orgunit-in-google-directory-api?noredirect=1&lq=1
            # Fortunately, when there are no custom OUs present, we won't
            # need to check if a setting change was made at the top-level
            # OU in the Rego; because no custom OUs have been created, any
            # changes have to apply to the top-level OU.
            return ""
        parent_ou = response['organizationUnits'][0]['parentOrgUnitId']
        response = service.orgunits().get(customerId='my_customer', orgUnitPath=parent_ou).execute()
        ou_name = response['name']
        return ou_name
    except Exception as exc:
        warnings.warn(
            f"Exception thrown while getting top level OU: {exc}",
            RuntimeWarning
        )
        return ""


def get_tenant_info(service) -> dict:
    '''
    Gets the high-level tenant info using the directory API

    :param service: a directory_v1 service instance
    '''
    try:
        response = service.domains().list(customer="my_customer").execute()
        primary_domain = ""
        for domain in response['domains']:
            if domain['isPrimary']:
                primary_domain = domain['domainName']
        return {
            'domain': primary_domain,
            'topLevelOU': get_toplevel_ou(service)
        }
    except Exception as exc:
        warnings.warn(
            f"An exception was thrown trying to get the tenant info: {exc}",
            RuntimeWarning
        )
        return {
            'domain': 'Error Retrieving',
            'topLevelOU': 'Error Retrieving'
        }


def get_gws_logs(products: list, service, event: str) -> dict:
    '''
    Gets the GWS admin audit logs with the specified event name.
    This function will also some parsing and filtering to ensure that an appropriate
    log event is matched to the appropriate product.
    This is to prevent the same log event from being duplicated
    across products in the resulting provider JSON.

    :param products: a narrowed list of the products being invoked
    :param service: service is a Google reports API object, created from successfully
    authenticating in auth.py
    :param event: the name of the specific event we are querying for.
    '''

    # Filter responses by org_unit id
    response = (service.activities().list(userKey='all',
            applicationName='admin',
            eventName=event).execute()).get('items', [])


    # Used for filtering duplicate events
    prod_to_app_name_values = {
        'calendar': ['Calendar'],
        'chat': ['Google Chat', 'Google Workspace Marketplace'],
        'commoncontrols': [
            'Security',
            'Google Workspace Marketplace',
            'Blogger',
            'Google Cloud Platform Sharing Options',
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
            for report in response:
                for events in report['events']:
                    parameters = events.get('parameters', [])
                    for parameter in parameters:
                        if parameter.get('name') == app_name:
                            param_val = parameter.get('value')
                            for prod, app_values in subset_prod_to_app_name.items():
                                if param_val in app_values:
                                    products_to_logs[prod].append(report)
        else: # no filtering append entire response to relevant product
            for prod in products:
                products_to_logs[prod].extend(response)
    except Exception as exc:
        warnings.warn(
            f"An exception was thrown while getting the logs; outputs will be incorrect: {exc}",
            RuntimeWarning
        )
    return products_to_logs

def get_group_settings(services) -> dict:
    '''
    Gets all of the group info using the directory API and group settings API

    :param services: a service instance
    '''

    try:
        # set up the services
        group_service = services['groups']
        domain_service = services['directory']
        # gather all of the domains within a suite to get groups
        response = domain_service.domains().list(customer="my_customer").execute()
        domains = {d['domainName'] for d in response['domains'] if d['verified']}

        # get the group settings for each groups
        group_settings = []
        for domain in domains:
            response = domain_service.groups().list(domain=domain).execute()
            for group in response.get('groups'):
                email = group.get('email')
                group_settings.append(group_service.groups().get(groupUniqueId=email).execute())
        return {'group_settings': group_settings}
    except Exception as exc:
        warnings.warn(
            f"Exception thrown while getting group settings; outputs will be incorrect: {exc}",
            RuntimeWarning
        )
        return {'group_settings': []}

def call_gws_providers(products: list, services, quiet) -> dict:
    '''
    Calls the relevant GWS APIs to get the data we need for the baselines.
    Data such as the admin audit log, super admin users etc.

    :param products: list of product names to check
    :param services: a dict of service objects.
    :param quiet: suppress tqdm output
    service is a Google reports API object, created from successfully authenticating in auth.py
    '''
    # create a inverse dictionary containing a mapping of event => list of products
    events_to_products = create_subset_inverted_dict(EVENTS, products)
    events_to_products_bar = tqdm(events_to_products.items(), leave=False, disable=quiet)

    # main aggregator dict
    product_to_logs = create_key_to_list(products)
    product_to_items = {}
    ou_ids = set()
    ou_ids.add("") # certain settings have no OU
    try:
        # Add top level organization unit name
        ou_ids.add(get_toplevel_ou(services['directory']))
        # get all organizational unit data
        product_to_items['organizational_units'] = get_ous(services['directory'])
        for orgunit in product_to_items['organizational_units']['organizationUnits']:
            ou_ids.add(orgunit['name'])
        # add just organizational unit names to a field]
        product_to_items['organizational_unit_names'] = list(ou_ids)
    except Exception as exc:
        warnings.warn(
            f"Exception thrown while getting tenant data: {exc}",
            RuntimeWarning
        )

    # call the api once per event type
    try:
        for event, product_list in events_to_products_bar:
            products = ', '.join(product_list)
            bar_descr = f"Running Provider: Exporting {event} events for {products}..."
            events_to_products_bar.set_description(bar_descr)

            # gets the GWS admin audit logs and merges them into product_to_logs
            # aggregator dict
            product_to_logs = merge_dicts(
                product_to_logs,
                get_gws_logs(
                    products=product_list,
                    service=services['reports'],
                    event=event
                )
            )
    except Exception as exc:
        warnings.warn(
            f"Provider Exception thrown while getting the logs; outputs will be incorrect: {exc}",
            RuntimeWarning
        )

    # repacks the main aggregator into the original form
    # that the api returns the data in; under an 'items' key.
    # Then we put this key under a {product}_log key for the Rego code
    try:
        for product, logs in product_to_logs.items():
            key_name = f"{product}_logs"
            product_to_items[key_name] = {'items': logs}

        # get tenant metadata for report front page header
        product_to_items['tenant_info'] = get_tenant_info(services['directory'])

        if 'gmail' in product_to_logs: # add dns info if gmail is being run
            product_to_items.update(get_dnsinfo(services['directory']))

        if 'commoncontrols' in product_to_logs: # add list of super admins if CC is being run
            product_to_items.update(get_super_admins(services['directory']))

        if 'groups' in product_to_logs:
            product_to_items.update(get_group_settings(services=services))

    except Exception as exc:
        warnings.warn(
            f"Uncaught Exception thrown while getting other data: {exc}",
            RuntimeWarning
        )
    return product_to_items
