"""
auth.py is the authentication module.

This module uses a local credential.json file to authenticate to a GWS org
"""

from __future__ import print_function
import os.path
from pathlib import Path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly',
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.customer.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/apps.groups.settings"]


def gws_auth(cred_path:str):
    """
    Generates an Oauth token for accessing Google's APIs

    :param cred_path: directory containing the credentials file
    """
    cred_dir = Path(cred_path).parent
    oauth_token = (cred_dir / 'token.json').resolve()

    creds = None
    if os.path.exists(oauth_token):
        creds = Credentials.from_authorized_user_file(oauth_token, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                cred_path, SCOPES)
            # the prompt parameter forces the user to consent to the token
            creds = flow.run_local_server(port=8080, prompt='consent')
        # Save the credentials for the next run
        with open(oauth_token, mode='w', encoding='UTF-8') as token:
            token.write(creds.to_json())
    return creds
