# Download the OPA executable

The tool makes use of [Open Policy Agent's Rego Policy language](https://www.openpolicyagent.org/docs/latest/policy-language/). There
are three ways users can obtain the OPA executable:

1. Using the provided setup utility
2. Using the provided getopa utility
3. Manually downloading the OPA executable.

## ScubaGoggles Setup Utility

The ScubaGoggles setup utility performs the initial configuration of ScubaGoggles,
including downloading OPA if needed. Execute it using the following command:

```shell
scubagoggles setup
```

> [!NOTE]
> The ScubaGoggles setup utility only needs to be run once, for the initial installation of ScubaGoggles, but may be run as many times as needed.
> It creates a `.scubagoggles` directory in your home directory and
> populates it with an OPA executable and a config file controlling several default ScubaGoggles parameters.
> There are several advanced configuration options for setup that allow users to indicate what values should be used for those defaults;
> advanced users may use these options now if desired, but those defaults can be configured at any time.
> See [Configuring Defaults](../installation/Defaults.md) for more details.

## OPTIONAL: Getopa Utility

You will only
need to download the OPA executable separately if you need a **specific**
version.  Otherwise, you may skip this step and continue to
[Prerequisites](../prerequisites/Prerequisites.md).

You may download the OPA executable, to either upgrade the version you
currently have or use a specific version, using the `scubagoggles getopa`
command:

```
scubagoggles getopa --help
usage: scubagoggles getopa [-h] [--nocheck] [--force] [--version <OPA-version>] [--opapath <directory>]

Download OPA executable

options:
  -h, --help            show this help message and exit
  --nocheck, -nc        Do not check hash code after download
  --force, -f           Overwrite existing OPA executable
  --version <OPA-version>, -v <OPA-version>
                        Version of OPA to download (default: latest version)
  --opapath <directory>, -r <directory>
                        Directory containing OPA executable (default: location established by setup)
```

```bash
# example
scubagoggles getopa -v v0.60.0
```

If you have run the [ScubaGoggles setup utility](DownloadAndInstall.md#ScubaGoggles-Setup-Utility),
you may have specified the location of the OPA executable. `getupa` will save the OPA executable to this location.  Optionally, you may specify an alternate location for the executable, such as a location that is in the PATH environment variable. If you experience issues with ScubaGoggles recognizing your OPA executable, rename the executable to `opa`.

## OPTIONAL: Downloading the OPA Executable from the OPA Website

1. If the above options can not execute for any reason or you would prefer to
   download OPA manually, go to the [Open Policy Agent website](https://www.openpolicyagent.org/docs/latest/#running-opa)
2. Check the website for a compatible OPA version (Currently v0.45.0 and above)
   for ScubaGoggles and select the corresponding version on top left of the
   website.
3. Navigate to the menu on left side of the screen:
   `Introduction -> Running OPA -> Download OPA`
4. Follow the instructions for downloading the respective OPA executable for
   your OS.
5. Rename the OPA executable to `opa`
6. Run `scubagoggles setup --opapath [path to executable]` to configure ScubaGoggles to use the newly downloaded executable as the default OPA location.

> [!NOTE]
> For linux and macOS, you must make sure the OPA executable has execute
> permission.  If you downloaded the OPA executable either during the setup
> process or using the `getopa`subcommand, the permission has already been set
> correctly.

```bash
# give the opa executable execute permissions
chmod u+x opa
```

## Navigation

- Continue to [Configuring Defaults](../installation/Defaults.md)
- Return to [Documentation Home](/README.md)
