
# Usage: Parameters
Execute the ScubaGoggles tool using the `scubagoggles` command. For GWS,
all commands will be under the `gws` "subcommand".

```
usage: scubagoggles gws [-h]
                        [--baselines <baseline> [<baseline> ...]]
                        [--outputpath <directory>]
                        [--outjsonfilename <output-JSON-file>]
                        [--credentials <credentials-JSON-file>]
                        [--config <YAML-config-file>]
                        [--subjectemail <email-address>]
                        [--customerid <customer-id>]
                        [--opapath <opa-directory>]
                        [--regopath <directory>]
                        [--documentpath <directory>]
                        [--outputfoldername <name>]
                        [--outputproviderfilename <name>]
                        [--outputactionplanfilename <name>]
                        [--outputregofilename <name>]
                        [--outputreportfilename]
                        [--preferreddnsresolvers <dns-resolvers> [<dns-resolvers> ...]]
                        [--quiet]
                        [--silencebodwarnings]
                        [--skipdoh]
                        [--numberofuuidcharacterstotruncate <number>]
                        [--debug]
                        [--runcached]
                        [--skipexport]
                        [--darkmode <boolean>]

SCuBA automated conformance check for Google Workspace (GWS) products

options:
  -h, --help            show this help message and exit
  --credentials <credentials-JSON-file>, -c <credentials-JSON-file>
                        The location and name of the OAuth / service account credentials json file. Required unless the
                        credentials path has been saved using the ScubaGoggles setup utility or an access token is
                        provided.
  --accesstoken <access-token>
                        Access token string to be used in lieu of a credentials file. If provided, will take precendence
                        over the credentials file. Advanced option; using a credentials file is the recommended
                        authentication method.
  --baselines <baseline> [<baseline> ...], -b <baseline> [<baseline> ...]
                        A list of one or more abbreviated GWS baseline names that the tool will assess. Defaults to all
                        baselines. Choices: assuredcontrols, calendar, chat, classroom, commoncontrols, drive, gemini,
                        gmail, groups, meet, sites.
  --outputpath <directory>, -o <directory>
                        The folder path where both the output JSON & HTML report will be created.
  --outjsonfilename <output-JSON-file>
                        The name of the file that encapsulates all assessment output. Defaults to ScubaResults.
  --config <YAML-config-file>
                        Local file path to a YAML formatted configuration file. Configuration file parameters can be
                        used in place of command-line parameters. Additional parameters and variables not available on
                        the command line can also be included in the file that will be provided to the tool for use in
                        specific tests.
  --subjectemail <email-address>
                        Only applicable when using a service account. The email address of a user the service account
                        should act on behalf of. This user must have the necessary privileges to run scubagoggles.
  --customerid <customer-id>
                        The customer ID the tool should run on. Defaults to "my_customer" which will be the domain of
                        the user / service account authenticating.
  --opapath <opa-directory>
                        The directory containing the OPA executable. Defaults to ~/.scubagoggles/.
  --regopath <directory>
                        The relative path to the directory contain the folder containing the rego files.
  --documentpath <directory>
                        The relative path to the directory containing the SCuBA baseline documents.
  --outputfoldername <name>
                        The name of the folder created in --outputpath where both the output JSON and the HTML report
                        will be created. Defaults to GWSBaselineConformance. The client's local timestamp will be
                        appended to this name.
  --outputproviderfilename <name>
                        The name of the Provider output json in --outputpath. Defaults to ProviderSettingsExport.
  --outputactionplanfilename <name>
                        The name of the Action Plan output csv in --outputpath. Defaults to ActionPlan.
  --outputregofilename <name>
                        The name of the Rego output json in --outputpath. Defaults to TestResults.
  --outputreportfilename
                        The name of the main html file homepage created in --outputpath. Defaults to BaselineReports.
  --preferreddnsresolvers <dns-resolvers>
                        IP addresses of DNS resolvers that should be used to retrieve any DNS records required by
                        specific SCuBA policies. Optional; if not provided, the system default will be used. Example:
                        --preferreddnsresolvers 8.8.8.8 8.8.4.4
  --quiet               This switch suppresses automatically launching a web browser to open the html report output and
                        the loading bar output.
  --silencebodwarnings  This switch suppresses warning relating to requirements specific to BOD compliance (e.g.,
                        documenting OrgName in the config file).
  --skipdoh             If true, do not fallback to DoH should the traditional DNS requests fail when retrieving any DNS
                        records required by specific SCuBA policies.
  --numberofuuidcharacterstotruncate <number>
                        Controls how many characters will be truncated from the report UUID when appended to the end of
                        outjsonfilename. Valid values are 0, 13, 18, 36. Defaults to 18.
  --debug               This switch is used to print debugging information for OPA.
  --darkmode            <boolean>
                        Enable dark mode styles for the report output
Cached Mode options:
  --runcached           This switch when added will run in the tool in "RunCached mode". When combined with --skipexport
                        allows the user to skip authentication and provider export.
  --skipexport          This switch when added will skip the provider export. To be used in conjunction with
                        --runcached.
```

## Navigation
- Continue to [Usage: Examples](Examples.md)
- Return to [Documentation Home](/README.md)
