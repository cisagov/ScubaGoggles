"""
scuba_constants.py is where short-hand references and full URLs to the GWS api calls are maintained.
Also used to centralize other constant values.
"""

from enum import Enum

BASE_URL_ADMINSDK = 'https://developers.google.com/admin-sdk'
BASE_URL_WORKSPACE_ADMIN = 'https://developers.google.com/workspace/admin'


class ApiReference(Enum):
    '''
    Enum for mapping code-friendly names of the various API calls to their short-hand reference
    '''
    LIST_USERS = 'directory/v1/users/list'
    LIST_OUS = 'directory/v1/orgunits/list'
    LIST_DOMAINS = 'directory/v1/domains/list'
    LIST_DOMAIN_ALIASES = '/directory/reference/rest/v1/domainAliases/list'
    LIST_GROUPS = 'directory/v1/groups/list'
    LIST_CUSTOMERS = 'directory/v1/customer/get'
    LIST_ACTIVITIES = 'reports/v1/activities/list'
    GET_GROUP = 'groups-settings/v1/groups/get'


class ApiUrl(Enum):
    '''
    Enum for mapping code-friendly names of the various API calls to their documentation URLs
    '''
    LIST_USERS = f'{BASE_URL_ADMINSDK}/directory/reference/rest/v1/users/list'
    LIST_OUS = f'{BASE_URL_ADMINSDK}/directory/reference/rest/v1/orgunits/list'
    LIST_DOMAINS = f'{BASE_URL_ADMINSDK}/directory/reference/rest/v1/domains/list'
    LIST_DOMAIN_ALIASES = f'{BASE_URL_WORKSPACE_ADMIN}/directory/reference/rest/v1/domainAliases/list'
    LIST_GROUPS = f'{BASE_URL_ADMINSDK}/directory/reference/rest/v1/groups/list'
    LIST_CUSTOMERS = f'{BASE_URL_ADMINSDK}/directory/v1/customer/get'
    LIST_ACTIVITIES = f'{BASE_URL_ADMINSDK}/reports/reference/rest/v1/activities/list'
    GET_GROUP = f'{BASE_URL_ADMINSDK}/groups-settings/v1/reference/groups/get'


# Dictionary mapping short-hand reference to <a> tags linking to the documentation
API_LINKS = {
    api.value: f'<a href="{ApiUrl[api.name].value}">{api.value}</a>' for api in ApiReference
}


OPA_VERSION = 'v1.0.1'

NUMBER_OF_UUID_CHARACTERS_TO_TRUNCATE_CHOICES = (
    0, 13, 18, 36
)
