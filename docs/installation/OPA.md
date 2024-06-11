
# Download the OPA executable

The tool makes use of [Open Policy Agent's Rego Policy language](https://www.openpolicyagent.org/docs/latest/policy-language/).
An OPA executable is required to execute this tool and can be downloaded using our `download_opa.py` script.

```
python download_opa.py --help
usage: download_opa.py [-h] [-v] [-os]

Download executable the OPA executable file required to run this SCuBA tool.

options:
  -h, --help            show this help message and exit
  -v {0.45.0,0.46.3,0.47.4,0.48.0,0.49.2,0.50.2,0.51.0,0.52.0,0.53.1,0.54.0,0.55.0,0.56.0,0.57.1,0.58.0,0.59.0,0.60.0}
                        What version of OPA to download: Default version: 0.59.0
  -os {windows,macos,linux}
                        Operating system version of OPA to download. Default os: windows
  --disablessl          If there are proxy errors, try adding this switch to disable ssl verification
```
```
# example
python download_opa.py -v 0.60.0 -os macos
```
1. If the above script can not execute for any reason or you would prefer to download OPA manually, go to the [Open Policy Agent website](https://www.openpolicyagent.org/docs/latest/#running-opa)
2. Check the website for a compatible OPA version (Currently v0.45.0 and above) for ScubaGoggles and select the corresponding version on top left of the website
3. Navigate to the menu on left side of the screen: `Introduction -> Running OPA -> Download OPA`
4. Follow the instructions for downloading the respective OPA executable for your OS.

> [!NOTE]
> The following notes apply only for MAC and Linux users.
- By default on MAC and Linux systems the OPA executable will be run with `sudo`.
- Use the `scubagoggles gws --omitsudo` flag to omit running the executable with `sudo`.
- MAC and Linux OS users should have their OPA executables named `opa_darwin_amd64` or `opa_linux_amd64_static` respectively for scubagoggles execution.
- The OPA executable must also be given execute permissions
```bash
chmod +x opa_darwin_amd64 # give the opa executable execute permissions
```

## Navigation
- Continue to [Prerequisites](/docs/prerequisites/Prerequisites.md)
- Return to [Documentation Home](/README.md)
