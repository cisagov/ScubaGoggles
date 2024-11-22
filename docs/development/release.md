**NOTE** The following documentation is for ScubaGoggles
developers.

# ScubaGoggles Release Procedure

## Setting the Version

Update the version in the code that matches the release version number, if this
hasn't been done already.  Use the `scubagoggles version --upgrade` command
to set the version.

Once changes in the repository have been frozen for the release, the release
branch (`main`) is tagged with the version.  Use an annotated tag to mark the
release:

```
git tag -a v1.0.0 -m 'ScubaGoggles version 1.0.0'
git push origin v1.0.0
```

## Building the Release

ScubaGoggles uses the Python packaging process as described in the
[Python Packaging User Guide](https://packaging.python.org/en/latest/).  The
`build` package is required, and is included in the `requirements.txt` file.
If `pip list` doesn't show that the `build` package is installed in your
environment, run `pip install -r requirements.txt` when your current working
directory is at the top-level directory of the ScubaGoggles repository (where
`requirements.txt` resides).

The `setuptools` backend is used to build the ScubaGoggles packages.  The
configuration (which was originally in `setup.py`) is in `pyproject.toml`.
Because there are files other than Python code, such as Markdown and Rego files,
the `MANIFEST.in` file is needed to ensure these other files are included with
the ScubaGoggles package.  These two configuration files, along with the
LICENSE file, are located at the repository top-level directory.

### Pre-release Review

Before building the release packages, review the `classifiers`, `dependencies`,
and `requires-python` configuration parameters in `pyproject.toml`.  If any of
the package dependencies change, the same changes must be reflected both in
both the `pyproject.toml` and `requirements.txt` files.

### Building ScubaGoggles Packages

ScubaGoggles is distributed using a binary "wheel" format, and a source code
version in a gzip-compressed "tar" format.  General users will install the
binary wheel package.

To build the packages, use the `scubagoggles/utils/build.sh` Bash script.
As it is written in Bash, it will require either Git or Cygwin on Windows.
Since Git is required for development, Git Bash should already be available
on a Windows system used for ScubaGoggles development.  Because this script
is written in Bash, it will work correctly on linux and macOS systems.

The following is the script usage:

```shell
$ scubagoggles/utils/build.sh -h
script usage: build.sh [options]

    -h: display usage and exit
    -o <dir>: create package files in this directory
    -r <git-repo>: ScubaGoggles Git repository specification
    -t <git-tag-or-branch>: checkout tag or branch for build
                            defaults to top of main branch
```

The script creates a clean environment for building the packages.  A Python
virtual environment is created in your temporary directory and the ScubaGoggles
Git repository is cloned into a subdirectory of your temporary directory.  These
temporary directories are cleaned up when the script exits.

The `-t` option allows you to provide a branch or tag that the repository will
be set to for the build.  For normal releases, this tag should be the release
tag (e.g., 'v1.0.0').  By default, the build is based on the HEAD of the main
branch.

When the build process completes, the binary and source package files are
copied to the current working directory when the script was run, or the
directory specified by the `-o` option.

This is an abbreviated example of running the build with its output to the
console:

```shell
$ scubagoggles/utils/build.sh
{build>>>} Creating new Python virtual environment for build...
{build>>>} Cloning Git repository...
<messages...>
{build>>>} Activate Python virtual environment...
{build>>>} Install requirements and editable ScubaGoggles...
<messages...>
{build>>>} Build distribution files...
<messages...>
Successfully built scubagoggles-x.x.x.tar.gz and scubagoggles-x.x.x-py3-none-any.whl
{build>>>} Copying <temp-dir>/scubagoggles-x.x.x-py3-none-any.whl to ./
{build>>>} Copying <temp-dir>/scubagoggles-x.x.x.tar.gz to ./
{build>>>} Performing build cleanup...
```
