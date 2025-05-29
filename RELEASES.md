# ScubaGoggles Release Process <!-- omit in toc --> #

This document outlines the ScubaGoggles software release process.

## Table of Contents <!-- omit in toc --> ##

- [Versioning](#versioning)
- [Release branches and tags](#release-branches-and-tags)
- [Preparing ScubaGoggles release candidate](#preparing-scubagoggles-release-candidate)
- [Publishing ScubaGoggles release candidate](#publishing-scubagoggles-release-candidate)

## Versioning ##

ScubaGoggles releases use the Semantic Versioning specification [v2.0](https://semver.org/spec/v2.0.0.html) to number its releases.  As such release versions take the form of MAJOR.MINOR.PATCH where:
* MAJOR version when you make incompatible API changes
* MINOR version when you add functionality in a backward compatible manner
* PATCH version when you make backward compatible bug fixes

Additional labels for pre-release and build metadata may also be used as extensions to the MAJOR.MINOR.PATCH format, as determined by the development team.

Note that ScubaGoggles versions and Secure Configuration Baseline (SCB) policy versions are distinct, but related.  That is, a given version of ScubaGoggles may operate on one or more SCB, or baseline, versions.  A given ScubaGoggles version assesses against the baseline version included in the release package.  ScubaGoggles reports include both the tool and baseline versions for reference.

## Release branches and tags ##

ScubaGoggles major and minor releases are built directly from the main branch.  Branch protections prevent direct push to the main branch.  All changes require a pull request and associated review prior to merge. 
When a new release is planned, the latest commit to be included is tagged with its release versions (e.g., vX.Y.Z). Patch versions are created from a separate release branch named `release/X.Y.Z` and are branched from the latest release tag or previous patch release branch which they are patching. The patch release branch contains only the cherry picked commits that resolve an identified bug the patch release resolves along with version bumps.

## Preparing ScubaGoggles release candidate ##

The checklist below is used by the development team when it prepares a new release.  The goal of the list below is to ensure consistency and quality in the resulting releases.

- [ ] Ensure all [blocked](https://github.com/cisagov/ScubaGoggles/labels/) issues and pull requests are resolved.
- [ ] (future) Update CHANGELOG
- [ ] Validate that all tests pass on CI for the release branch before proceeding
- [ ] Update __version__ in [__init__.py](https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/__init__.py) to match release version
- [ ] Update the ScubaGoggles and SCB version in the [README.md](https://github.com/cisagov/ScubaGoggles/blob/main/README.md) badge image links.
- [ ] Update and redact the sample report using the redaction tool and manual review
- [ ] Check README for any necessary changes and documentation updates as needed
- [ ] Build initial release candidate by manually triggering [`Build Draft Release`](https://github.com/cisagov/ScubaGoggles/actions/workflows/run_release.yml) workflow with expected release name (vX.X.X) and release version (X.X.X) based on semantic versioning
- [ ] Conduct release testing of each baseline
- [ ] Fix critical defects deemed release blocking
- [ ] Document non-critical issues for future development cycle
- [ ] If fixes applied, restart release process

## Publishing ScubaGoggles release candidate ##

After running the `Build Draft Release` workflow, a draft release will be visible to development team members for review and revision. The checklist below is designed to ensure consistency in review and publishing of the release candidate as the final release. 

- [ ] Update release notes manually
  - Adjust default change format to use PR listing as `- #{{TITLE}} ##{{NUMBER}}`
  - Regroup changes into sections: Major new features, Bug fixes, Documentation improvements, and Baseline updates
- [ ] Make the release official and visible to public
  - Uncheck **Set as a pre-release**
  - Check **Set as latest release**
  - Click **Publish Release**
- [ ] Verify the new release is shown as latest on GitHub repository main page
- [ ] Validate that the GitHub release contains both the scubagoggles-X.Y.Z.tar.gz and scubagoggles-X.Y.Z-py3-none-any.whl files
- [ ] Verify the [`Publish ScubaGoggles to PyPI`](https://github.com/cisagov/ScubaGoggles/actions/workflows/publish_to_pypi.yml) workflow is triggered after publishing the GitHub release
- [ ] Verify the release is displayed on the cisagov [pypi.org](https://pypi.org/user/cisagov/) page
