# Authentication Methods

ScubaGoggles supports both OAuth and Service Accounts for authorization/authentication. See the following table for the tradeoffs between the two methods.

| OAuth    | Service Account |
| -------- | ------- |
| + Allows user consent to specific scopes | - Requires Domain-Wide Delegation (DWD) for the Policy API and a Delegated Admin Service Account (DASA) for read-only access to the Group Settings API. |
| - Requires a browser for authentication | + Does not require a browser for authentication, allowing for more automation. |

After determining which method is most appropriate for your organization, follow the instructions in either [Using OAuth](OAuth.md) or [Using a Service Account](ServiceAccount.md).

## Navigation
- Continue to [Using OAuth](OAuth.md)
- Continue to [Using a Service Account](ServiceAccount.md)
- Return to [Documentation Home](/README.md)
