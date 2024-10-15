# Upgrading and Maintenance

## Upgrading ScubaGoggles
Assuming you installed ScubaGoggles as described in [Download and Install](/docs/installation/DownloadAndInstall.md), upgrading to the lastest version of ScubaGoggles should be as simple as:
- Repeating the steps described in [Download and Install](/docs/installation/DownloadAndInstall.md) with the new release.
- Making the OPA executable available, by either:
    - downloading the executable again as described in [Download the OPA executable](/docs/installation/OPA.md),
    - copying the executable from the old release folder to the new release folder, or
    - using the `--opapath` parameter to tell ScubaGoggles where to look for the executable.
- Making your credentials available, by either:
    - copying your `credentials.json` file to the new release folder or
    - using the `--credentials` parameter to tell ScubaGoggles where to look for your credentials.

If instead you cloned the ScubaGoggles repo and wish to run ScubaGoggles on the latest code from main (only recommended for development purposes), be sure to run `python -m pip install .` inside the ScubaGoggles directory after pulling the latest code.

## Upgrading OPA
While new versions of OPA are periodically released, it is only necessary to upgrade OPA if the version you have locally is unsupported. Running `python download_opa.py --help` lists the supported OPA versions.

Upgrading OPA is as simple as downloading the desired executable, which can be done by running the `download_opa.py` script again. See [Download the OPA executable](/docs/installation/OPA.md) for detailed instructions.

## Navigation
- Return to [Documentation Home](/README.md)