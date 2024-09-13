
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

## Navigation
- Continue to [Usage: Examples](/docs/usage/Examples.md)
- Return to [Documentation Home](/README.md)