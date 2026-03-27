
# ScubaGoggles Parameters
The scubagoggles gws cmdlet has several command-line parameters, which are described below.

> **Note**: Some parameters can also be specified in a [configuration file](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Config.md). If specified in both, command-line parameters have precedence over the config file.

Execute the ScubaGoggles tool using the `scubagoggles` command. For GWS,
all commands will be under the `gws` "subcommand".

## Help

**-h or --help** is the help function to pull up additional information on all of the commands available for scubagoggles gws

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | String |
| Default     | n/a    |
| Config File | n/a    |

Here is an example using `-h or --help`:

```powershell
# using the help command
scubagoggles gws --help
```

## Credentials

**-c or --credentials** is the location and name of the OAuth / service account credentials json file. Required unless the credentials path has been saved using the ScubaGoggles setup utility or an access token is provided.

| Parameter   | Value                                    |
|-------------|------------------------------------------|
| Optional    | Yes                                      |
| Datatype    | String                                   |
| Default     | path indicated through the setup utility |
| Config File | Yes                                      |

Here is an example using `-c or --credentials`:

```powershell
# identify the location and name of the OAuth / service account credentials json file
scubagoggles gws --credentials C:\users\johndoe\Documents\scuba\credentials.json
```

## Access Token

**--accesstoken** string to be used in lieu of a credentials file. If provided, will take precendence over the credentials file. Advanced option; using a credentials file is the recommended authentication method.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | String |
| Default     | n/a    |
| Config File | Yes    |

Here is an example using `--accesstoken`:

```powershell
# identify access token to be used in lieu of a credentials file
scubagoggles gws --accesstoken <access-token>
```

## Baselines

**-b or --baselines** string to list of one or more abbreviated GWS baseline names that the tool will assess. Defaults to all baselines. Choices: assuredcontrols, calendar, chat, classroom, commoncontrols, drive, gemini, gmail, groups, meet, sites.

| Parameter   | Value                                             |
|-------------|---------------------------------------------------|
| Optional    | Yes                                               |
| Datatype    | List of Strings                                   |
| Default     | ["assuredcontrols", "calendar", "chat", "classroom", "commoncontrols", "drive", "gemini", "gmail", "groups", "meet", "sites"] |
| Config File | Yes                                               |

The list of acceptable values are:

| Product                                      | Product Name    |
|----------------------------------------------|-----------------|
| Assured Controls                             | assuredcontrols |
| Google Calendar                              | calendar        |
| Google Chat                                  | chat            |
| Google Classroom                             | classroom       |
| Common Controls                              | commoncontrols  |
| Google Drive                                 | drive           |
| Google Gemini                                | gemini          |
| Gmail                                        | gmail           |
| Groups for Business                          | groups          |
| Google Meet                                  | meet            |
| Google Sites                                 | sites           |

Here is an example using `--baselines`:

```powershell
# Assess two products
scubagoggles gws --baselines chat, meet 
```
>**Note**: baselines are separated by commas.

## Output Path

**-o or --outputpath** is the folder path where both the output JSON & HTML report will be created. The folder will be created if it does not exist.

| Parameter   | Value                                      |
|-------------|--------------------------------------------|
| Optional    | Yes                                        |
| Datatype    | String                                     |
| Default     | Path indicated through the setup utility. If not configured during the setup, default to the directory where ScubaGoggles is executed. |
| Config File | Yes                                        |

Here is an example using `--outputpath`:

```powershell
# Change the output path
scubagoggles gws --outputpath <directory>
```
> **Note**: Path can be absolute or relative.

## Output file JSON Name

**--outjsonfilename** is the name of the file that encapsulates all assessment output. Defaults to ScubaResults.

| Parameter   | Value               |
|-------------|---------------------|
| Optional    | Yes                 |
| Datatype    | String              |
| Default     | `ScubaResults_UUID` |
| Config File | Yes                 |

Here is an example using `--outjsonfilename`:

```powershell
# Change the output path
scubagoggles gws --outjasonfilename <output-JSON-file>
```
## Configuration File Path

**--config** identifies the local file path to a YAML formatted configuration file. Configuration file parameters can be used in place of command-line parameters. Additional parameters and variables not available on the command line can also be included in the file that will be provided to the tool for use in specific tests.

| Parameter   | Value     |
|-------------|-----------|
| Optional    | Yes       |
| Datatype    | String    |
| Default     | n/a       |
| Config File | No        |

Here is an example using `--config`:

```powershell
# Set the inputs using a configuration file
scubagoggles gws --config C:\users\johndoe\Documents\scuba\config.json
```
If `--config` is specified, default values will be used for any parameters that are not added to the config file. These default values are shown in the [full config file](https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/sample-config-files/full_config.yaml).

More information about the configuration file can be found on the [configuration page](https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Config.md).

> **Note**: Path can be absolute or relative.

## Subject Email Address

**--subjectemail** Only applicable when using a service account. The email address of a user the service account should act on behalf of. This user must have the necessary privileges to run scubagoggles.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | String |
| Default     | n/a    |
| Config File | Yes    |

Here is an example using `--subjectemail`:

```powershell
# email address of a user of the service account should act on behalf of
scubagoggles gws --subjectemail johndoe@cisa.dhs.gov
```
## Customer ID

**--customerid** The customer ID the tool should run on. Defaults to "my_customer" which will be the domain of the user / service account authenticating.

| Parameter   | Value       |
|-------------|-------------|
| Optional    | Yes         |
| Datatype    | String      |
| Default     | my_customer |
| Config File | Yes         |

Here is an example using `--customerid`:

```powershell
# email address of a user of the service account should act on behalf of
scubagoggles gws --customerid <customer-id>
```

## OPA Path 

**- --opapath** is the location of the folder that contains the Open Policy Agent (OPA) policy engine executable file. Defaults to ~/.scubagoggles/.

| Parameter   | Value                            |
|-------------|----------------------------------|
| Optional    | Yes                              |
| Datatype    | String                           |
| Default     | path indicated through the setup utility |
| Config File | Yes                              |

Here is an example using ` --opapath`:

```powershell
# Change the directory that contains the OPA exe
scubagoggles gws  --opapath C:\Users\johndoe\Downloads
```
> **Note**: Path can be absolute or relative.

## Rego Path

**--regopath** The relative path to the directory containing the rego files.

| Parameter   | Value                            |
|-------------|----------------------------------|
| Optional    | Yes                              |
| Datatype    | String                           |
| Default     | The "rego" folder within the ScubaGoggles installation folder |
| Config File | Yes                              |

Here is an example using `--regopath`:

```powershell
# Change the path to the directory containing the rego files
scubagoggles gws --regopath C:\Users\johndoe\Downloads
```
## Document Path

**--documentpath** The relative path to the directory containing the SCuBA baseline documents files.

| Parameter   | Value                            |
|-------------|----------------------------------|
| Optional    | Yes                              |
| Datatype    | String                           |
| Default     | `C:\Users\johndoe\.scubagoggles\`|
| Config File | Yes                              |

Here is an example using `--documentpath`:

```powershell
# Change the path to the directory containing the SCuBA baseline documents
scubagoggles gws --documentpath C:\Users\johndoe\Downloads
```
## Output Folder Name

** --outputfoldername** The name of the folder created in --outputpath where both the output JSON and the HTML report will be created. Defaults to GWSBaselineConformance. The client's local timestamp will be appended to this name.

| Parameter   | Value                   |
|-------------|-------------------------|
| Optional    | Yes                     |
| Datatype    | String                  |
| Default     | `GWSBaselineConformance`|
| Config File | Yes                     |

Here is an example using `--outputfoldername`:

```powershell
# Change the name of the folder created in --outputpath where both the output JSON and the HTML report will be created
scubagoggles gws  --outputfoldername testing
```
## Output Folder Name

**--outputproviderfilename** the name of the Provider output json in --outputpath. Defaults to ProviderSettingsExport.

| Parameter   | Value                   |
|-------------|-------------------------|
| Optional    | Yes                     |
| Datatype    | String                  |
| Default     | `ProviderSettingsExport`|
| Config File | Yes                     |

Here is an example using `--outputproviderfilename`:

```powershell
# Change the provider settings file name
scubagoggles gws  --outputproviderfilename mysettings
```
## Output ActionPlan file name

**--outputactionplanfilename** the name of the Action Plan output csv in --outputpath. Defaults to ActionPlan.

| Parameter   | Value       |
|-------------|-------------|
| Optional    | Yes         |
| Datatype    | String      |
| Default     | `ActionPlan`|
| Config File | Yes         |

Here is an example using `--outputactionplanfilename`:

```powershell
# Change name of the Action Plan output csv
scubagoggles gws  --outputactionplanfilename myplan
```

## Output rego file name

**--outputregofilename** the name of the Rego output json in --outputpath. Defaults to TestResults.

| Parameter   | Value        |
|-------------|--------------|
| Optional    | Yes          |
| Datatype    | String       |
| Default     | `TestResults`|
| Config File | Yes          |

Here is an example using `--outputregofilename`:

```powershell
# Change name of the Rego output json
scubagoggles gws  --outputregofilename myresults
```

## Output report file name

**--outputreportfilename** the name of the main html file homepage created in --outputpath. Defaults to BaselineReports.

| Parameter   | Value            |
|-------------|------------------|
| Optional    | Yes              |
| Datatype    | String           |
| Default     | `BaselineReports`|
| Config File | Yes              |

Here is an example using `--outputreportfilename`:

```powershell
# Change name the main html file homepage created
scubagoggles gws  --outputreportfilename myreport
```
## Preferred DNS Resolvers

**--preferreddnsresolvers** is a list of IP addresses of DNS resolvers that should
be used to retrieve any DNS records required by specific SCuBA policies. Currently,
the only applicable SCuBA polices are the following:
- GWS.GMAIL.2.1
- GWS.GMAIL.3.1
- GWS.GMAIL.4.1
- GWS.GMAIL.4.2
- GWS.GMAIL.4.3
- GWS.GMAIL.4.4

Optional; if not provided, the system default resolver will be used.

| Parameter   | Value           |
|-------------|-----------------|
| Optional    | Yes             |
| Datatype    | List of strings |
| Default     | []              |
| Config File | Yes             |

Here is an example using `--preferreddnsresolvers`:

```powershell
scubagoggles gws --preferreddnsresolvers 8.8.8.8 8.8.4.4
```
## Quiet

**--Quiet** this switch suppresses automatically launching a web browser to open the html report output and the loading bar output.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | Switch |
| Default     | n/a    |
| Config File | Yes    |

Here is an example using `--quiet`:

```powershell
scubagoggles gws --quiet
```

## Silence BOD warnings

**--silencebodwarnings** silences warnings relating to BOD submissions requirements, e.g., the requirement to document `OrgName` in the config file.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | Switch |
| Default     | n/a    |
| Config File | Yes    |

```powershell
# Silence warning related to BOD submission requirements
scubagoggles gws --silencebodwarnings
```
## Skip DoH

**--skipdoh** allows the user to disable the DoH fallback which would normally be
done if the traditional DNS requests fail when retrieving any DNS records
required by specific SCuBA policies. See [PreferredDnsResolvers](#preferreddnsresolvers)
for the list of applicable policies.

| Parameter   | Value   |
|-------------|---------|
| Optional    | Yes     |
| Datatype    | Boolean |
| Default     | $false  |
| Config File | Yes     |

Here is an example using `--skipdoh`:

```powershell
scubagoggles gws --skipdoh
```

## Number of UUID characters to truncate

**--numberofuuidcharacterstotruncate** controls how many characters will be truncated from the report UUID when appended to the end of **outjsonfilename**.

| Parameter   | Value              |
|-------------|--------------------|
| Optional    | Yes                |
| Datatype    | Integer            |
| Default     | 18                 |
| Config File | Yes                |


The list of acceptable values are:

| Description                            | Value      |
|----------------------------------------|------------|
| Do no truncation of the appended UUID  | 0          |
| Remove one octet of the appended UUID  | 13         |
| Remove two octets of the appended UUID | 18         |
| Remove the appended UUID completely    | 36         |

Here is an example using `--numberofuuidcharacterstotruncate`:
```powershell
# Truncate the UUID at the end of OutJsonFileName by 18 characters
scubagoggles gws --numberofuuidcharacterstotruncate 18
```
## Debug OPA 

**--debug** This switch is used to print debugging information for OPA.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | Switch |
| Default     | n/a    |
| Config File | Yes   |

```powershell
# print debugging information for OPA
scubagoggles gws --debug
```
## Dark Mode

**--darkmode** enables the HTML report to have a dark mode look.

| Parameter   | Value    |
|-------------|----------|
| Optional    | Yes      |
| Datatype    | Boolean  |
| Default     | n/a      |
| Config File | Yes      |

```powershell
# View the HTML report in dark mode
scubagoggles gws --darkmode
```
## Report Redaction

**--reportredaction** enables identification information redaction styles for the report output.

| Parameter   | Value    |
|-------------|----------|
| Optional    | Yes      |
| Datatype    | Boolean  |
| Default     | n/a      |
| Config File | Yes      |

```powershell
# Enable identification information redaction styles for the report output
scubagoggles gws --reportredaction
```
## Run cache mode 

**--runcached** switch when added will run the tool in "RunCached mode". When combined with --skipexport allows the user to skip authentication and provider export.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | Switch |
| Default     | n/a    |
| Config File | Yes    |

```powershell
# run the tool in "RunCached mode"
scubagoggles gws --runcached 
```
## Skip Export

**--skipexport** will skip the provider export. To be used in conjunction with --runcached.

| Parameter   | Value  |
|-------------|--------|
| Optional    | Yes    |
| Datatype    | Switch |
| Default     | n/a    |
| Config File | Yes    |

```powershell
# run the tool in "RunCached mode" and skip the provider export
scubagoggles gws --runcached --skipexport
```
## Navigation
- Continue to [Usage: Examples](Examples.md)
- Return to [Documentation Home](/README.md)
