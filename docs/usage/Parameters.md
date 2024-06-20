
# Usage: Parameters
Execute the ScubaGoggles tool using the `scubagoggles` command. For GWS, all commands will be under the `gws` subparser.

```
scubagoggles gws -h
usage: scubagoggles gws [-h] [-b  [...]] [-o] [-c] [--subjectemail] [--customerid] [--opapath] [--regopath] [--documentpath]
                    [--runcached] [--skipexport] [--outputfoldername] [--outputproviderfilename]
                    [--outputregofilename] [--outputreportfilename] [--omitsudo] [--quiet] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -b  [ ...], --baselines  [ ...]
                        A list of one or more abbreviated GWS baseline names that the tool will assess. Defaults to
                        all baselines. Choices: gmail, calendar, groups, chat, drive, meet, sites, commoncontrols,
                        rules, classroom
  -o , --outputpath     The folder path where both the output JSON & HTML report will be created. Defaults to "./" The
                        current directory.
  -c , --credentials    The relative path and name of the OAuth / service account credentials json file. Defaults to
                        "./credentials.json" which means the tool will look for the file named credentials.json in the
                        current directory.
  --outjsonfilename     The name of the file that encapsulates all assessment output. Defaults to ScubaResults.
  --subjectemail        Only applicable when using a service account. The email address of a user the service account
                        should act on behalf of. This user must have the necessary privileges to run scubagoggles.
  --customerid          The customer ID the tool should run on. Defaults to "my_customer" which will be the domain of
                        the user / service account authenticating.
  --opapath             The relative path to the directory containing the OPA executable. Defaults to "./" the current
                        executing directory.
  --regopath            The relative path to the directory contain the folder containing the rego files. Defaults to
                        "./rego" the "rego" folder inside the current executing directory.
  --documentpath        The relative path to the directory containing the SCuBA baseline documents. Defaults to
                        "./baselines" the "baselines" folder inside the current executing directory.
  --runcached           This switch when added will run in the tool in "RunCached mode". When combined with -sa allows
                        to the user to skip authentication and provider export.
  --skipexport          This switch when added will skip the provider export.To be used in conjunction with
                        --runcached.
  --outputfoldername    The name of the folder created in --outputpath where both the output JSON and the HTML report
                        will be created. Defaults to GWSBaselineConformance. The client's local timestamp will be
                        appended to this name.
  --outputproviderfilename
                        The name of the Provider output json in --outputpath. Defaults to ProviderSettingsExport.
  --outputregofilename
                        The name of the Rego output json in --outputpath. Defaults to TestResults.
  --outputreportfilename
                        The name of the main html file homepage created in --outputpath. Defaults to BaselineReports.
  --omitsudo            This switch prevents running the OPA executable with sudo.
  --quiet               This switch suppresses automatically launching a web browser to open the html report output
                        and the loading bar output.
  --debug               This switch is used to print debugging information for OPA.
```

## Navigation
- Continue to [Usage: Examples](/docs/usage/Examples.md)
- Return to [Documentation Home](/README.md)