
# Usage: Config File
All ScubaGoggles [parameters](Parameters.md) can be placed into a configuration file in order to made execution easier. The path of the file is specified by the `--config` parameter, and its contents are expected as YAML.

> [!NOTE]
> If a parameter is specified both on the command-line and in a configuration file, the command-line parameter has precedence over the config file.

## Sample Configuration Files
[Sample config files](../../scubagoggles/sample-config-files) are available in the
repo and are discussed below. When executing ScubaGoggles, only a single config
file can be read in; we recommend looking through the following examples and
constructing a config file that best suits your use case.

### SCuBA Compliance Configuration
The [SCuBA compliance](../../scubagoggles/sample-config-files/scuba_compliance.yaml)
is the **recommended starting point** for organizations seeking to meet SCuBA
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

### Full Configuration Reference

The [full config file](../../scubagoggles/sample-config-files) shows **all available parameters** supported by ScubaGoggles specified in the config file. This serves as a complete reference for all possible configuration options. Any parameter may be commented out - if not specified or commented out, ScubaGoggles will supply the default value unless overridden on the command line.

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
- GWS.GMAIL.4.4v0.6

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

## Navigation
- Continue to [Usage: Examples](Examples.md)
- Return to [Documentation Home](/README.md)
