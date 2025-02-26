# Using a Service Account
Only complete this section if not authenticating via [OAuth](OAuth.md). See [Authentication Methods](AuthenticationMethods.md) for more details.

> [!Important]
> ScubaGoggles requires the service account to have [domain-wide delegation of authority](https://support.google.com/a/answer/162106?hl=en) to function.

1. Login to https://console.cloud.google.com and navigate to your GCP project.
1. From the hamburger menu, select **IAM & Admin** -> **Service Accounts**
1. Select **CREATE SERVICE ACCOUNT**. Fill out the id field and then select **DONE**
1. Click on the newly created service account then click **KEYS** -> **ADD KEY** -> **Create new key** -> **JSON** -> **CREATE**
1. Optionally run the following command to configure ScubaGoggles to use those credentials by default: `scubagoggles setup --credentials [path to JSON credentials file]`. If you skip this step, by default ScubaGoggles will look for a file called "credentials.json" in the current working directory of the user calling ScubaGoggles. Alternatively, the credentials path can be indicated at run time using the `credentials` parameter (see [Parameters](/docs/usage/Parameters.md)).
1. Now login to [admin.google.com](https://admin.google.com/) and navigate to **Security** -> **Access and data control** -> **API controls**
1. Select **MANAGE DOMAIN WIDE DELEGATION**
1. Select **Add new**
1. Enter the `client_id` from the downloaded credentials (also visible after clicking on the created Service account under Details -> Unique ID)
1. Enter each OAuth scope as listed in [Permissions](../prerequisites/Prerequisites.md#permissions)
1. Select **AUTHORIZE**
1. Finally, run ScubaGoggles with the `--subjectemail` option set to the email of an admin with necessary permissions to run ScubaGoggles.

> [!NOTE]
> ScubaGoggles can be run using a service account in a different organization.
> To do so, specify the `--customerid` argument with the customer ID of the target organization (found in [admin.google.com](https://admin.google.com/) under **Account** -> **Account settings**)

## Navigation
- Continue to [Usage: Parameters](../usage/Parameters.md)
- Return to [Documentation Home](/README.md)
