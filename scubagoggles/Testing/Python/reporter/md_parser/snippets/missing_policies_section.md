# CISA Google Workspace Secure Configuration Baseline for Gmail

# Baseline Policies

## 1. Mail Delegation

This section determines whether users can delegate access to their mailbox to others within the same domain. This delegation includes access to read, send, and delete messages on the account owner's behalf. This delegation can be done via a command line tool (GAM) if enabled in the admin console.

<!-- Intentionally missing the `### Policies` section -->

### Resources

-   [Google Workspace Admin Help: Turn Gmail delegation on or off](https://support.google.com/a/answer/7223765?hl=en)
-   [GAM: Example Email Settings - Creating a Gmail delegate](https://github.com/GAM-team/GAM/wiki/ExamplesEmailSettings#creating-a-gmail-delegate)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

- None

#### GWS.GMAIL.1.1v0.6 Instructions
To configure the settings for Mail Delegation:
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **User Settings -\> Mail delegation**.
4.  Ensure that the **Let users delegate access to their mailbox to other users in the domain** checkbox is unchecked.
5.  Select **Save**.