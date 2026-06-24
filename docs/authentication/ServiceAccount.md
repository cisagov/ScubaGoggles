# Using a Service Account
Only complete this section if not authenticating via [OAuth](OAuth.md). See [Authentication Methods](AuthenticationMethods.md) for more details.

> [!Important]
> ScubaGoggles requires the service account to have [domain-wide delegation of authority](https://support.google.com/a/answer/162106?hl=en) to function. 

1. Login to https://console.cloud.google.com and navigate to your GCP project.
1. From the hamburger menu, select **IAM & Admin** -> **Service Accounts**
1. Select **+ Create service account**. Fill out the id field and then select **Done**
1. Copy the email associated with your service account, for later use
1. Click on the newly created service account then click **Keys** -> **Add key** -> **Create new key** -> **JSON** -> **Create**
1. Move the credentials file to a safe location. There is no set location requirement for this file, but it should be saved somewhere it won't be inadvertently deleted or accessed by unauthorized entities.
1. Optionally run the following command to configure ScubaGoggles to use those credentials by default: `scubagoggles setup --credentials [path to JSON credentials file]`. If you skip this step, you will be required to indicate the path at run time using the `credentials` parameter (see [Parameters](/docs/usage/Parameters.md)).
1. Now login to [admin.google.com](https://admin.google.com/) and navigate to **Security** -> **Access and data control** -> **API controls**
1. Select **MANAGE DOMAIN WIDE DELEGATION**
1. Select **Add new**
1. Enter the `client_id` from the downloaded credentials (also visible after clicking on the created Service account under Details -> Unique ID)
1. Enter each OAuth scope as listed in [Permissions](../prerequisites/Prerequisites.md#permissions)
1. Select **AUTHORIZE**

> [!NOTE]
> The Groups Settings API does not natively support a read-only API scope out-of-the-box. To achieve least privilege and to resolve risk concerns around `update` operations available through the Group Settings API, we use the Groups Reader role with Delegated Admin Service Account (DASA) authorization. 

1. To add the Groups Reader role to your service account, navigate to **Account** -> **Admin Roles**
1. Locate the Groups Reader role, click on **Actions** -> **Assign Admin**
1. Click on **Assign service accounts**
1. Search for your service account using its associated email and click **ADD**
1. Under Set Conditions, ensure that **Access to all groups** is selected and click **ASSIGN ROLE**
1. Return to https://console.cloud.google.com. Open the menu on the left and click **APIs and Services** -> **Enabled API Services**
1. On the toolbar, click **+ Enable APIs & Services**
1. Search for and enable the **Admin SDK API**
1. Search for and enable the **Groups Settings API**
1. Search for and enable the **Cloud Identity** API
1. Finally, run ScubaGoggles with the `--subjectemail` option set to the email of a Workspace admin user with necessary permissions to run ScubaGoggles.  Do **not** use the service account email you created in a previous step.

> [!NOTE]
> ScubaGoggles can be run using a service account in a different organization.
> To do so, specify the `--customerid` argument with the customer ID of the target organization (found in [admin.google.com](https://admin.google.com/) under **Account** -> **Account settings**)

## Navigation
- Continue to [Usage: Parameters](../usage/Parameters.md)
- Return to [Documentation Home](/README.md)
