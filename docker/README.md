# ScubaGoggles Access-Token Container

This directory builds a ScubaGoggles container image that authenticates with a
Google Workspace OAuth access token instead of a Google service account key.

The image does not copy credentials into the image, does not set
`GOOGLE_APPLICATION_CREDENTIALS`, and the default Kubernetes manifest disables
Kubernetes service account token mounting with `automountServiceAccountToken:
false`.

## Build

The build script copies the local ScubaGoggles source into a temporary Docker
build context and installs it into the image. OPA is copied from the official
`openpolicyagent/opa` Docker Hub image during the multi-stage build.

```sh
./build.sh
```

Defaults:

- ScubaGoggles source: `<your_path>`
- Image tag: `scubagoggles-access-token:local`
- OPA image version: `1.17.0`

Override either value if needed:

```sh
SCUBAGOGGLES_SOURCE=/path/to/ScubaGoggles \
IMAGE_TAG=us-docker.pkg.dev/PROJECT/REPOSITORY/scubagoggles-access-token:TAG \
OPA_VERSION=1.17.0 \
./build.sh
```

## Run Locally

Provide the access token at runtime. The token is rendered into a temporary
container-local config file so it is not passed to ScubaGoggles as a command
line argument.

```sh
docker run --rm \
  -e SCUBAGOGGLES_ACCESS_TOKEN="$SCUBAGOGGLES_ACCESS_TOKEN" \
  -e SCUBAGOGGLES_CUSTOMER_ID="my_customer" \
  -v "$PWD/output:/output" \
  scubagoggles-access-token:local
```

Useful environment variables:

- `SCUBAGOGGLES_ACCESS_TOKEN`: OAuth access token to use for Google APIs.
- `ACCESS_TOKEN`: fallback token variable if `SCUBAGOGGLES_ACCESS_TOKEN` is not set.
- `SCUBAGOGGLES_CUSTOMER_ID`: Google Workspace customer ID. Defaults to `my_customer`.
- `SCUBAGOGGLES_OUTPUT_PATH`: report output directory. Defaults to `/output`.
- `SCUBAGOGGLES_BASELINES`: optional comma- or space-separated baselines.
- `SCUBAGOGGLES_CONFIG`: optional mounted YAML config file to merge before token settings.

Additional ScubaGoggles `gws` arguments can be appended to the container
command. The entrypoint rejects `--credentials`, `-c`, `--subjectemail`, and
`--config`; use `SCUBAGOGGLES_CONFIG` for mounted config files so the entrypoint
can merge the access token safely.


The example uses a PVC named `scubagoggles-output` for reports. Replace that
volume with your cluster's preferred output storage.
