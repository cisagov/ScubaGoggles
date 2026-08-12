# Prerequisites

## Permissions

### OAuth scopes

ScubaGoggles requires the user to have Super Admin role to successfully run the tool.
When authenticating interactively via OAuth, you will be prompted to consent to the following scopes:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly,
https://www.googleapis.com/auth/admin.directory.domain.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,
https://www.googleapis.com/auth/admin.directory.customer.readonly,
https://www.googleapis.com/auth/cloud-identity.policies.readonly,
https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly,
https://www.googleapis.com/auth/apps.licensing
https://www.googleapis.com/auth/apps.groups.settings
```

### Domain-wide delegation scopes

When authenticating via a service account, authorize the following scopes under domain-wide delegation:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly,
https://www.googleapis.com/auth/admin.directory.domain.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,
https://www.googleapis.com/auth/admin.directory.customer.readonly,
https://www.googleapis.com/auth/cloud-identity.policies.readonly,
https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly
```

## Google Cloud APIs

In addition to consenting to the scopes above, the following APIs must be
enabled in your Google Cloud project (see [Using OAuth](../authentication/OAuth.md)
or [Using a Service Account](../authentication/ServiceAccount.md) for steps):

- **Admin SDK API**
- **Groups Settings API**
- **Cloud Identity API**
- **Enterprise License Manager API** (required for license and subscription data
  in the Common Controls report)

Additionally, because the Groups Settings API does not natively support a read-only API scope, we use the Groups Reader role with Delegated Admin Service Account (DASA) authorization to achieve least privilege and address the risks associated with the update operations available through the Groups Settings API.

## Create a Project
1. If you already have a Google Cloud Project that you want to utilize skip to [Authentication Methods](../authentication/AuthenticationMethods.md)
2. Otherwise start by signing into http://console.cloud.google.com/.
3. Follow the [directions outlined in this guide to create a project](https://developers.google.com/workspace/guides/create-project)

## Navigation
- Continue to [Authentication Methods](../authentication/AuthenticationMethods.md)
- Return to [Documentation Home](/README.md)
