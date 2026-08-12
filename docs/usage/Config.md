
# Usage: Config File

> [!TIP]
> Prefer a graphical interface? The [Configuration UI](../../scubagoggles/ui/README.md) provides a web-based form for building config files with validation, policy browsing, and YAML export.

All ScubaGoggles [parameters](Parameters.md) can be placed into a configuration file in order to made execution easier. The path of the file is specified by the `--config` parameter, and its contents are expected as YAML.

> [!NOTE]
> If a parameter is specified both on the command-line and in a configuration file, the command-line parameter has precedence over the config file.

## Who is this for?

ScubaGoggles configuration files are intended for:

- **Google Workspace administrators** running SCuBA baseline assessments against their tenant
- **Security and compliance teams** documenting policy omissions, annotations, and organizational context in assessment reports
- **Federal agencies and other SCuBA adopters** meeting baseline requirements, including fields such as `orgname` and `orgunitname`
- **Assessors and IT staff** who need repeatable, version-controlled settings instead of long command-line invocations

If you are new to ScubaGoggles configuration, start with the [SCuBA compliance sample](../../scubagoggles/sample-config-files/scuba_compliance.yaml) or use the [Configuration UI](../../scubagoggles/ui/README.md) to build your first file interactively.

## Which config path should I use?

You can configure ScubaGoggles in three ways. They produce the same YAML format and can be combined (for example, build a file in the UI, then run it with `--config`).

| Approach | Best for | How to start |
|----------|----------|--------------|
| **Configuration UI** | First-time users, browsing policies, omit/annotate workflows with validation | `python -m scubagoggles.ui.launch` — see the [Configuration UI guide](../../scubagoggles/ui/README.md) |
| **Sample YAML files** | Copy-paste starting points for common scenarios | Browse [sample config files](../../scubagoggles/sample-config-files/README.md) |
| **Hand-edited YAML** | Advanced users, automation, or CI pipelines | Start from [full_config.yaml](../../scubagoggles/sample-config-files/full_config.yaml) |

Command-line flags still work alongside a config file; any parameter passed on the command line overrides the value in the file.

## Sample Configuration Files
[Sample config files](../../scubagoggles/sample-config-files/README.md) are available in the
repo and are discussed below. When executing ScubaGoggles, only a single config
file can be read in; we recommend looking through the following examples and
constructing a config file that best suits your use case.

### Basic Configuration
The [basic config](../../scubagoggles/sample-config-files/basic_config.yaml) is a **minimal starting point** for a baseline assessment. It includes organization documentation fields and a small set of baselines without omit policies, annotations, or advanced options.

### SCuBA Compliance Configuration

The [SCuBA compliance](../../scubagoggles/sample-config-files/scuba_compliance.yaml)
configuration is the **recommended starting point** for organizations seeking to meet SCuBA
compliance checks. This configuration file contains:

- Parameters necessary for service account authentication
- Additional organizational documentation fields
- Fields for omitting or annotating ScubaGoggles policy checks

Users are highly encouraged to read all the configuration file documentation
sections to understand what each field is for and to modify those fields to
successfully pass ScubaGoggles's SCuBA baseline compliance checks.

This configuration file includes the additional `orgname` and `orgunitname`
fields for documenting the organization and organizational subunit owner of the
GWS tenant ScubaGoggles is running against.

### Omit Policy Example

The [omit policy example](../../scubagoggles/sample-config-files/omit_policy_example.yaml) shows how to exclude policies with `rationale` and optional `expiration` dates. You can create the same structure in the Configuration UI under the **Omit Policies** tab — see [Omitting policies with the Configuration UI](#omitting-policies-with-the-configuration-ui).

### Output Path Example

The [output path example](../../scubagoggles/sample-config-files/output_path_example.yaml) demonstrates how to set `outputpath` and customize report file names.

### Full Configuration Reference

The [full config file](../../scubagoggles/sample-config-files/full_config.yaml) shows **all available parameters** supported by ScubaGoggles specified in the config file. This serves as a complete reference for all possible configuration options. Any parameter may be commented out - if not specified or commented out, ScubaGoggles will supply the default value unless overridden on the command line.

**Note**: Default values do not apply to authentication parameters

ScubaGoggles can be invoked with this config file:
```
scubagoggles gws --config full_config.yaml
```


### Omit Policies

In some cases, it may be appropriate to omit specific policies from ScubaGoggles evaluation. For example:
- When a policy is implemented by a third-party service that ScubaGoggles does not audit.
- When a policy is not applicable to your organization (e.g., policy GWS.GMAIL.4.3, which is only applicable to federal, executive branch, departments and agencies).

The `omitpolicy` top-level key allows the user to specify the policies that should be omitted from the
ScubaGoggles report. Omitted policies will show up as "Omitted" in the HTML
report and will be colored gray. Omitting policies must only be done if the
omissions are approved within an organization's security risk management
process. **Exercise care when omitting policies because this can inadvertently
introduce blind spots when assessing your system.**

For each omitted policy, the config file allows you to indicate the following:
- `rationale`: The reason the policy should be omitted from the report. This value will be displayed in the "Details" column of the report. ScubaGoggles will output a warning if no rationale is provided.
- `expiration`: Optional. A date after which the policy should no longer be omitted from the report. The expected format is yyyy-mm-dd.

Example YAML (also available in [omit_policy_example.yaml](../../scubagoggles/sample-config-files/omit_policy_example.yaml)):

```
omitpolicy:
  GWS.GMAIL.1.1v1:
    rationale: "Accepting risk for now; will reevaluate at a later date."
    expiration: "2030-12-31"
```

#### Omitting policies with the Configuration UI

The [Configuration UI](../../scubagoggles/ui/README.md) provides an **Omit Policies** tab for building `omitpolicy` entries without hand-editing YAML:

1. Launch the UI: `python -m scubagoggles.ui.launch`
2. On the **Main** tab, select the baselines that include the policies you may omit
3. Open the **Omit Policies** tab and browse policies by product
4. Click **Omit** on a policy, enter a **rationale** (required for good practice), and optionally set an **expiration** date
5. Go to **Preview** and download the YAML file
6. Run ScubaGoggles with your exported file:

```
scubagoggles gws --config scubagoggles_config.yaml
```

You can also import an existing config (including [omit_policy_example.yaml](../../scubagoggles/sample-config-files/omit_policy_example.yaml)) with the **Open** button in the UI header, review or adjust omissions, and re-export.

See the [Configuration UI guide](../../scubagoggles/ui/README.md#omitting-policies) for screenshots and a step-by-step walkthrough.

### Annotate Policies

ScubaGoggles supports annotating results for individual policies. Annotated policies will be shown in the HTML with the
annotation appended to the details column. Annotated policies are intended to:
- Document action plans for any failed controls. ScubaGoggles will output a warning for any failing controls that are not
documented in the config file, though this warning can be silenced with the `-silencebodwarnings` flag.
- Allow users to identify incorrect results
- Help contextualize results

The `annotatepolicy` top-level key allows the user to specify the policies that should be annotated.

For each annotated policy, the config file allows you to indicate the following:
- `incorrectresult`: Boolean, whether or not to mark the result incorrect. Optional, defaults to false.
- `comment`: The annotation to add to the report. A warning will be printed if control is marked incorrect with no comment provided as justification.
- `remediationdate`: Optional. The date a failing control is anticipated to be implemented. The expected format is yyyy-mm-dd.

**Exercise care when marking incorrect results because this can inadvertently introduce blind spots when assessing your system.**

### Break Glass Accounts

In some cases, it may be appropriate to specify the number of break glass accounts to be omitted from the total admin count. For example:
- When a policy is looking for the total number of break glass accounts (e.g. policy GWS.COMMONCONTROLS.6.2).

The `breakglassaccounts` top-level key allows the user to specify the break glass accounts to exclude from the admin count. The number of break glass accounts will be shown on the ScubaGoggles report.

### DNS Configuration
The following SCuBA polices depend on the capability to make DNS requests:
- GWS.GMAIL.2.1v0.6
- GWS.GMAIL.3.1v0.6
- GWS.GMAIL.4.1v0.6
- GWS.GMAIL.4.2v0.6
- GWS.GMAIL.4.3v0.6
- GWS.GMAIL.2.1
- GWS.GMAIL.3.1
- GWS.GMAIL.4.1
- GWS.GMAIL.4.2
- GWS.GMAIL.4.3
- GWS.GMAIL.4.4

In some cases, it can be helpful to control where those DNS requests are
sent to (see [ScubaGoggles lists failures for the SPF, DKIM, and DMARC policies (GWS.GMAIL.2 through GWS.GMAIL.4) even though you have published the applicable DNS records](/docs/troubleshooting/Troubleshooting.md#scubagoggles-lists-failures-for-the-spf-dkim-and-dmarc-policies-gwsgmail2-through-gwsgmail4-even-though-you-have-published-the-applicable-dns-records)). ScubaGoggles provides two options for
configuring how DNS queries are made: `preferreddnsresolvers` and `skipdoh`.

#### preferreddnsresolvers
IP addresses of DNS resolvers that should be used to retrieve any DNS records
required by the specific SCuBA policies listed above. Optional; if not provided,
the system default will be used.

Example config file usage:
```
preferreddnsresolvers:
    - 8.8.8.8
    - 8.8.4.4
```

Example CLI usage:
```
scubagoggles gws --preferreddnsresolvers 8.8.8.8 8.8.4.4
```

#### skipdoh
If true, do not fallback to DoH should the traditional DNS requests fail when
retrieving any DNS records required by the specific SCuBA policies listed above.

Example config file usage:
```
skipdoh: true
```

Example CLI usage:
```
scubagoggles gws --skipdoh
```

### IMAP Exclusions
Per GWS.GMAIL.9.1, IMAP MAY be enabled on a per-OU or per-group basis when there is a specific need.
The `imapexclusions` top-level key allows the user to specify OUs and groups where IMAP is allowed.
Each entry in the `imapexclusions` list accepts the following fields:
-  `ou`: Org unit where IMAP should be allowed. Cannot be the workspace's top-level OU. The OU must
    be input as a path relative to the top-level OU. Examples:
        - `My OU`
        - `My OU/My sub OU`.
-  `group`: Group where IMAP should be allowed. Enter as the group email rather than the display
    name, e.g., `examplegroup@example.com`.
- `justification`: A brief explanation of why the OU/group should be excluded from the IMAP check.

`justification` is optional, but either `ou` or `group` must be provided. If both `ou` and `group`
are provided, the exception only applies to users that are in both the OU and the group.

### Sites Exclusions
Per GWS.SITES.1.1, Sites MAY be enabled on a per-OU or per-group basis when there is a specific need.
The `sitesexclusions` top-level key allows the user to specify OUs and groups where Sites is allowed.
Each entry in the `sitesexclusions` list accepts the following fields:
-  `ou`: Org unit where Sites should be allowed. Cannot be the workspace's top-level OU. The OU must
    be input as a path relative to the top-level OU. Examples:
        - `My OU`
        - `My OU/My sub OU`.
-  `group`: Group where Sites should be allowed. Enter as the group email rather than the display
    name, e.g., `examplegroup@example.com`.
- `justification`: A brief explanation of why the OU/group should be excluded from the Sites check.

`justification` is optional, but either `ou` or `group` must be provided. If both `ou` and `group`
are provided, the exception only applies to users that are in both the OU and the group.


## Navigation
- Continue to [Usage: Examples](Examples.md)
- Return to [Documentation Home](/README.md)
