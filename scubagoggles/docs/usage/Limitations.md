# Limitations

The majority of the conformance checks done by ScubaGoggles rely on [GWS Admin log events](https://support.google.com/a/answer/4579579?hl=en). If there is no log event corresponding to a SCuBA baseline policy, ScubaGoggles will indicate that the setting currently can not be checked on its HTML report output. In this situation, we recommend you manually review your GWS security configurations with the SCuBA security baselines.

Additionally, some events will not be visible due to data retention time limits, as the admin logs are only retained for 6 months (see [Data retention and lag times](https://support.google.com/a/answer/7061566)). However, if you wish to generate a log event for testing ScubaGoggles' capabilities, follow the implementation instructions in the [SCuBA GWS baseline documents](/baselines/README.md) to change your GWS configuration settings. Toggling certain settings, off and on will be enough to generate a log event. Other settings will require implementing more substantive configuration changes.

Many controls can be scoped down to the organizaitonal unit (OU) or group level. ScubaGoggles is capable of checking settings applied at these levels. However, for any setting that can be scoped to specific OUs or groups, ScubaGoggles asserts that at least one event is present for the organization's top-level OU. If no event can be found for the top-level OU, ScubaGoggles will not display any results for that control and instead display a warning, such as the following:
![image](https://github.com/cisagov/ScubaGoggles/assets/106177711/e3bf7925-8c00-489d-8e79-262e861bd1a8)

## Navigation
- Return to [Documentation Home](/README.md)
