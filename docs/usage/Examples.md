
# Usage: Examples
## Example 1: Run an assessment against all GWS products
```
scubagoggles gws
```

## Example 2: Run an assessment against just Gmail and Google Calendar
```
scubagoggles gws -b gmail calendar
```

## Example 3: Run an assessment and store the results under a folder called output
```
scubagoggles gws -b calendar gmail groups chat meet sites -o ./output
```

## Example 4: Do a run cached assessment
```
# skip authentication and provider export stage
# used for running against a cached provider json

scubagoggles gws --runcached --skipexport
```

## Example 5: Run with a service account on a different tenant
```
scubagoggles gws --customerid <customer_id> --subjectemail admin@example.com
```

See the `help` options yourself
```
scubagoggles gws -h
```

The html report should open automatically. If not, navigate to the output folder and open the `*.html` file using a browser of your choice. The json output will also be located in this folder.

> [!NOTE]
> If you chose not install the `scubagoggles` package in a venv but do have the dependencies installed from `requirements.txt`, you may execute the tool using the `scuba.py` script located in the root directory of this repository. Replace any `scubagoggles` directions with `python scuba.py`

## Navigation
- Continue to [Reviewing Output](/docs/usage/ReviewOutput.md)
- Return to [Documentation Home](/README.md)