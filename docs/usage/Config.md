
# Usage: Config File
All ScubaGoggles [parameters](/docs/usage/Parameters.md) can be placed into a configuration file in order to made execution easier. The path of the file is specified by the `--config` parameter, and its contents are expected as YAML.

> [!NOTE]
> If a parameter is specified both on the command-line and in a configuration file, the command-line parameter has precedence over the config file.

## Sample Configuration Files
[Sample config files](/sample-config-files) are available in the repo and are discussed below.

### Basic Usage
The [basic use](/sample-config-files/basic_config.yaml) example config file specifies the `outpath`, `baselines`, and `quiet` parameters.

ScubaGoggles can be invokes with this config file:
```
scubagoggles gws --config basic_config.yaml
```

It can also be invoked while overriding the `baselines` parameter.
```
scubagoggles gws --config basic_config.yaml -b gmail chat
```

## Omit Policies

In some cases, it may be appropriate to omit specific policies from ScubaGoggles evaluation. For example:
- When a policy is implemented by a third-party service that ScubaGoggles does not audit
- When a policy is not applicable to your organization (e.g., policy GWS.GMAIL.4.3v0.3 is only applicable to federal, executive branch, departments and agencies)

The `OmitPolicy` top-level key, shown in this [example ScubaGoggles configuration file](https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/Sample-Config-Files/omit_policies.yaml), allows the user to specify the policies that should be omitted from the ScubaGear report. Omitted policies will show up as "Omitted" in the HTML report and will be colored gray. Omitting policies must only be done if the omissions are approved within an organization's security risk management process. **Exercise care when omitting policies because this can inadvertently introduce blind spots when assessing your system.**

For each omitted policy, the config file allows you to indicate the following:
- `Rationale`: The reason the policy should be omitted from the report. This value will be displayed in the "Details" column of the report. ScubaGear will output a warning if no rationale is provided.
- `Expiration`: Optional. A date after which the policy should no longer be omitted from the report. The expected format is yyyy-mm-dd.


## Navigation
- Continue to [Usage: Examples](/docs/usage/Examples.md)
- Return to [Documentation Home](/README.md)
