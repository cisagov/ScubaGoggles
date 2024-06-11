# Permissions

The tool uses the following OAUTH API scopes:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly,
https://www.googleapis.com/auth/admin.directory.domain.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/apps.groups.settings
```


When running ScubaGoggles for the first time you will be prompted to consent to these API scopes. Users with the Super Admin role automatically have the privilege to consent to these scopes. A custom admin role can also be made with the minimum permissions to consent to these scopes. See this [Google Admin SDK Prerequisites guide](https://developers.google.com/admin-sdk/reports/v1/guides/prerequisites) for more information.

<!-- TODO create copy-paste friendly version of scope list-->

## Navigation
- Continue to [Create a Project](/docs/prerequisites/CreateAProject.md)
- Return to [Documentation Home](/README.md)


<!-- TODO segway into create a project>