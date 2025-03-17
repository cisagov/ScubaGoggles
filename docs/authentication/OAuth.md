# Using OAuth

Only complete this section if not authenticating via [Service Account](ServiceAccount.md). See [Authentication Methods](AuthenticationMethods.md) for more details.

## Create an OAuth credential

1. Sign in to your account at http://console.cloud.google.com/.
2. Click the "hamburger" menu on the left (three horizontal
   bars on top of each other), and select **APIs & Services** -> **OAuth consent screen**
3. Select **Internal** for **User Type**
4. Click **Create**
5. Fill in your **App name** and **User support email**
6. Scroll down to the **Authorized Domains** section
7. Under **Authorized domains**, add the primary domain of your GWS organization.
8. Add another email address for **Developer contact information**
9. Click **SAVE AND CONTINUE**
10. Do nothing on the **Scopes** screen, just click **SAVE AND CONTINUE**
11. Review summary, then click **BACK TO DASHBOARD**
12. Click **Credentials** from the menu on the left
13. Click **CREATE CREDENTIALS**
14. Select **Oauth client ID**
15. Select **Web application** for **Application type**
16. Give name as appropriate
17. Under **Authorized redirect URIs**, click "ADD URI." Add `http://localhost`
    and `http://localhost:8080/`. **NOTE** the ending slash (`/`) in the *second*
    URL is **necessary**.  If the slash is missing, you will eventually get an
    error when running ScubaGoggles (It will be an "access blocked" error on the
    Google authentication webpage.  You'll also see `Error 400: redirect_uri_mismatch`).
18. Click **CREATE**
19. Click **DOWNLOAD JSON** from the resulting **OAuth client created** page
20. Click **OK**
21. Move the credentials file to a safe location. There is no set location requirement for this file, but it should be saved somewhere it won't be inadvertently deleted or accessed by unauthorized entities.
22. Optionally run the following command to configure ScubaGoggles to use those credentials by default: `scubagoggles setup --credentials [path to JSON credentials file]`. If you skip this step, you will be required to indicate the path at run time using the `credentials` parameter (see [Parameters](/docs/usage/Parameters.md)).
23. Go back the menu on the left and click **Enabled API Services**
24. In the center screen click **Enabled APIs & Services**
25. Search for and enable the **Admin SDK API**
26. Search for and enable the **Groups Settings API**
27. Search for and enable the **Cloud Identity API**
28. During the first run of this tool your default web browser will open up a page to consent to the API scopes needed to run this tool. Sign in
    with an account with the necessary privileges and click allow.

## Add the Oauth App to the allowlist

If you've limited application access to Google's APIs in your organization, the [Common Controls: App Access to Google APIs](../../scubagoggles/baselines/commoncontrols.md#10-app-access-to-google-apis) baseline covers this topic, follow the directions below to allowlist the OAuth app.

1. Login to https://console.cloud.google.com
2. Navigate to the appropriate project
3. Select **API's & Services** from the top left hamburger icon
4. Select **Credentials**
5. Copy your client ID under **OAuth 2.0 Client IDs**
6. Now login to [admin.google.com](https://admin.google.com/) and navigate to **Security** -> **Access and Data Control** -> **API Controls** -> **Manage Third-Party App Access**
7. Select **Add App** -> **Oauth App Name** or **Client ID**
8. Search by your **OAuth client ID**
9. Select the App
10. Select your root organization as the domain
11. Select **Trusted**

## Navigation

- Continue to [Usage: Parameters](../usage/Parameters.md)
- Return to [Documentation Home](/README.md)
