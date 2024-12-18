
# Download the OPA executable

The tool makes use of [Open Policy Agent's Rego Policy language]
(https://www.openpolicyagent.org/docs/latest/policy-language/).  By default,
the `scubagoggles setup` command downloads the OPA executable.  You will only
need to download the OPA executable separately if you need a **specific**
version.  Otherwise, you may skip this step and continue to
[Prerequisites](../prerequisites/Prerequisites.md).

You may download the OPA executable, to either upgrade the version you
currently have or use a specific version, using the `scubagoggles getopa`
command:

```
scubagoggles getopa --help
usage: scubagoggles getopa [-h] [--nocheck] [--force] [--version <OPA-version>] [--opa_directory <directory>]

Download OPA executable

options:
  -h, --help            show this help message and exit
  --nocheck, -nc        Do not check hash code after download
  --force, -f           Overwrite existing OPA executable
  --version <OPA-version>, -v <OPA-version>
                        Version of OPA to download (default: latest version)
  --opa_directory <directory>, -r <directory>
                        Directory containing OPA executable (default: location established by setup)
```
```bash
# example
scubagoggles getopa -v v0.60.0
```

If you have run the [ScubaGoggles setup utility](DownloadAndInstall.md#ScubaGoggles-Setup-Utility),
you will have specified the location of the OPA executable.  This location is
used by `getopa` when downloading the OPA executable.  Optionally, you may
download the executable to a location that is in the PATH environment variable.

## Downloading the OPA Executable from the OPA Website

1. If the above script can not execute for any reason or you would prefer to
   download OPA manually, go to the [Open Policy Agent website]
   (https://www.openpolicyagent.org/docs/latest/#running-opa)
2. Check the website for a compatible OPA version (Currently v0.45.0 and above)
   for ScubaGoggles and select the corresponding version on top left of the
   website.
3. Navigate to the menu on left side of the screen:
   `Introduction -> Running OPA -> Download OPA`
4. Follow the instructions for downloading the respective OPA executable for
   your OS.

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
- Continue to [Prerequisites](../prerequisites/Prerequisites.md)
- Return to [Documentation Home](/README.md)
