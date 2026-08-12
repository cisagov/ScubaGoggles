# Sample Configuration Files

These YAML files illustrate common ScubaGoggles configuration scenarios. Pick the
one closest to your use case, copy it, and customize the values for your
organization.

| File | Use when you want to… |
|------|------------------------|
| [basic_config.yaml](basic_config.yaml) | Run a baseline assessment with minimal settings |
| [scuba_compliance.yaml](scuba_compliance.yaml) | Start from the recommended SCuBA compliance template (all 11 baselines) |
| [omit_policy_example.yaml](omit_policy_example.yaml) | Exclude specific policies with documented rationale |
| [output_path_example.yaml](output_path_example.yaml) | Control where reports are written and how they are named |
| [full_config.yaml](full_config.yaml) | See every supported parameter with inline comments |

## Building configs with the Configuration UI

If you prefer a graphical interface, use the [Configuration UI](../ui/README.md)
to build or edit these settings and export a YAML file:

```bash
python -m scubagoggles.ui.launch
```

You can also import any of the sample files above into the UI with the **Open**
button, make changes, and download an updated configuration from the **Preview**
tab.

## Documentation

- [Usage: Config File](../../docs/usage/Config.md)
- [Configuration UI](../ui/README.md)
