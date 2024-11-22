# Review Output
## Locating the Output

ScubaGoggles conformance reports are written to the output
directory you established during the [setup](../installation/DownloadAndInstall.md#scubagoggles-setup-utility) installation
step.  For each `scubagoggles gws` run, a subdirectory is
created, which is named in the following format:
`GWSBaselineConformance_yyyy_mm_dd_hh_mm_ss`, the suffix
of which is based on the date & time the report was
generated:

| Abbreviation | Description |
|-------------|---------------------------------------------------|
| yyyy | Four digit year (e.g., 2025). |
| mm | Two digit month. |
| dd | Two digit day. |
| hh | Two digit hour (24-hour time). |
| mm | Two digit minute. |
| ss | Two digit seconds. |

Unless run with the `--quiet` parameter, the HTML report will open automatically using the system's default browser.

See [Usage: Parameters](Parameters.md) for more details on these and other parameters.

## Output Format
The output will be saved in both HTML and json formats. See [Sample Report](../../scubagoggles/sample-report) for an example of the output.

## Purging Older Report Directories

Each time you run ScubaGoggles, a directory (folder) is created that contains
the conformance report files.  If you run ScubaGoggles often, these directories
will accumulate.  When you use the default output directory and directory name
prefix (`GWSBaselineConformance`), you may use the `scubagoggles purge`
command to remove older report directories.  The `--expire` option deletes all
report directories created earlier than the number of days specified.  The
`--keep` option ensures that the number of directories you specify will not be
deleted.  When given together, the keep count takes precedence over the expiry
days.


## Navigation
- Continue to [Limitations](Limitations.md)
- Return to [Documentation Home](/README.md)
