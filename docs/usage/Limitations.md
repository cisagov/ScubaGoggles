# Limitations

While most of the conformance checks done by ScubaGoggles rely on Google's Policy
API that provides direct access to your GWS settings, some settings are not
available from this API.  For a few conformance checks where the corresponding
settings are not provided by the Policy API, we try to determine the settings
using [GWS Admin log events](https://support.google.com/a/answer/4579579?hl=en).

All tests that rely on the reports API will be marked in the HTML report like so:

![image](https://github.com/user-attachments/assets/4f40fe87-fbfb-4669-9b71-c7a4c5079da1)


There are several key limitations associated with the log-based checks:
1. **No visibility if a setting has never been changed.** If a setting has never
been modified from its default state, ScubaGoggles will be unable to determine its
state as there will be no log events to assess. For these cases, ScubaGoggles will
indicate that it was unable to determine the current state on its HTML report output.
In this situation, we recommend you manually review your GWS security configurations
with the SCuBA secure baselines.
1. **No historic data.** Additionally, some events will not be visible due to data
retention time limits, as the admin logs are only retained for 6 months
(see [Data retention and lag times](https://support.google.com/a/answer/7061566)).
1. **Limited visibility into custom OUs.** Many controls can be scoped down to the
organizational unit (OU) or group level. ScubaGoggles is capable of checking settings
applied at these levels. For any setting that can be scoped to specific OUs or groups,
ScubaGoggles asserts that at least one event is present for the organization's top-level
OU. If no event can be found for the top-level OU, ScubaGoggles will report that it was
unable to determine the current state and recommend a manual check. However, ScubaGoggles
does _not_ assert that at least one event is present for each custom OU. If a custom OU
has no event, ScubaGoggles assumes that it inherits the setting from its parent. In
practice, this will often be the case but is by no means guaranteed. For example, if a
setting for a custom OU was changed over 6 months ago, ScubaGoggles will not be able to
see the corresponding log event and will assume it inherits the setting from its parent,
which in-fact is not the case.

For all the above limitations, any ScubaGoggles result that is marked as dependent on
log events should be viewed with a healthy degree of skepticism as missing results
and false negatives are possible.

## Navigation
- Return to [Documentation Home](/README.md)
