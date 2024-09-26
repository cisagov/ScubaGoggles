
# Usage: Config File
All ScubaGoggles [parameters](/docs/usage/Parameters.md) can be placed into a configuration file in order to made execution easier. The path of the file is specified by the `--config` parameter, and its contents are expected as YAML.

> [!NOTE]
> If a parameter is specified both on the command-line and in a configuration file, the command-line parameter has precedence over the config file.

## Sample Configuration Files
[Sample config files](/sample-config-files) are available in the repo and are discussed below. When executing ScubaGoggles, only a single config file can be read in; we recommend looking through the following examples and constructing a config file that best suits your use case.

### Basic Usage
The [basic use](/sample-config-files/basic_config.yaml) example config file specifies the `outpath`, `baselines`, and `quiet` parameters.

ScubaGoggles can be invoked with this config file:
```
scubagoggles gws --config basic_config.yaml
```

It can also be invoked while overriding the `baselines` parameter.
```
scubagoggles gws --config basic_config.yaml -b gmail chat
```

### Omit Policies

In some cases, it may be appropriate to omit specific policies from ScubaGoggles evaluation. For example:
- When a policy is implemented by a third-party service that ScubaGoggles does not audit.
- When a policy is not applicable to your organization (e.g., policy GWS.GMAIL.4.3v0.3, which is only applicable to federal, executive branch, departments and agencies).

The `omitpolicy` top-level key, shown in this [example ScubaGoggles configuration file](/sample-config-files/omit_policies.yaml), allows the user to specify the policies that should be omitted from the ScubaGoggles report. Omitted policies will show up as "Omitted" in the HTML report and will be colored gray. Omitting policies must only be done if the omissions are approved within an organization's security risk management process. **Exercise care when omitting policies because this can inadvertently introduce blind spots when assessing your system.**

For each omitted policy, the config file allows you to indicate the following:
- `rationale`: The reason the policy should be omitted from the report. This value will be displayed in the "Details" column of the report. ScubaGoggles will output a warning if no rationale is provided.
- `expiration`: Optional. A date after which the policy should no longer be omitted from the report. The expected format is yyyy-mm-dd.


## Navigation
- Continue to [Usage: Examples](/docs/usage/Examples.md)
- Return to [Documentation Home](/README.md)
