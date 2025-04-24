# Using OAuth

Only complete this section if not authenticating via [Service Account](ServiceAccount.md). See [Authentication Methods](AuthenticationMethods.md) for more details.

## Create an OAuth credential

1. Sign in to your account at http://console.cloud.google.com/.
2. Click the "hamburger" menu on the left (three horizontal
   bars on top of each other), and select **APIs & Services** -> **OAuth consent screen**
3. Click **Get started**
4. Fill in your **App name** and select your **User support email**. Click **Next**
5. Under **Audience**, choose **Internal**. Click **Next**
6. Under **Contact Information**, add an email address. Click **Next**
7. Select the checkbox to agree to the Google API Services: Users Data Policy. Click **Continue**
8. Click **Create**
9. On the sidebar, click **Branding**
10. Under **Authorized domains**, click **+ Add domain**, add the primary domain of your GWS organization, then click **Save**
11. Click the "hamburger" menu on the left, and select **APIs & Services** -> **Credentials**
12. Click **+ Create credentials**
13. Select **OAuth client ID**
14. Under **Application type**, select **Web application**
15. Give name as appropriate
16. Under **Authorized redirect URIs**, click **+ Add URI**. Add `http://localhost`
    and `http://localhost:8080/`. **NOTE** the ending slash (`/`) in the *second*
    URL is **necessary**.  If the slash is missing, you will eventually get an
    error when running ScubaGoggles (It will be an "access blocked" error on the
    Google authentication webpage.  You'll also see `Error 400: redirect_uri_mismatch`).
17. Click **Create**
18. Click **Download JSON** from the resulting **OAuth client created** page
19. Click **OK**
20. Move the credentials file to a safe location. There is no set location requirement for this file, but it should be saved somewhere it won't be inadvertently deleted or accessed by unauthorized entities.
21. Optionally run the following command to configure ScubaGoggles to use those credentials by default: `scubagoggles setup --credentials [path to JSON credentials file]`. If you skip this step, you will be required to indicate the path at run time using the `credentials` parameter (see [Parameters](/docs/usage/Parameters.md)).
22. Go back to menu on the left and click **APIs and Services** -> **Enabled API Services**
23. On the toolbar, click **+ Enable APIs & Services**
24. Search for and enable the **Admin SDK API**
25. Search for and enable the **Groups Settings API**
26. Search for and enable the **Cloud Identity** API
27. During the first run of this tool your default web browser will open up a page to consent to the API scopes needed to run this tool. Sign in
    with an account with the necessary privileges and click allow.

## Add the Oauth App to the allowlist

If you've limited application access to Google's APIs in your organization, the [Common Controls: App Access to Google APIs](../../scubagoggles/baselines/commoncontrols.md#10-app-access-to-google-apis) baseline covers this topic, follow the directions below to allowlist the OAuth app.

1. Login to https://console.cloud.google.com
2. Navigate to the appropriate project
3. Select **API's & Services** from the top left hamburger icon
4. Select **Credentials**
5. Copy your client ID under **OAuth 2.0 Client IDs**
6. Now login to [admin.google.com](https://admin.google.com/) and navigate to **Security** -> **Access and Data Control** -> **API Controls** -> **MANAGE THIRD-PARTY APP ACCESS**
7. Select **Configure new app**
8. Search by your **OAuth client ID**
9. Select the App
10. Under **Scope**, select your root organization as the domain. Click **Continue**
11. Under **Access to Google Data**, select **Trusted**. Click **Continue**
12. Click **Finish**

## Navigation

- Continue to [Usage: Parameters](../usage/Parameters.md)
- Return to [Documentation Home](/README.md)
