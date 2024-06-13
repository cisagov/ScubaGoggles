# Troubleshooting

## Lots of Manual Checks
The report output by ScubaGoggles may indicate that many manual checks are needed (e.g., https://github.com/cisagov/ScubaGoggles/issues/260). This is a symptom of ScubaGoggles' primary limitation. As the API calls to check most of the settings relevant to ScubaGoggles are have not been made public by Google, ScubaGoggles relies on [GWS Admin log events](https://support.google.com/a/answer/4579579?hl=en) to determine the current state. If there are no log events corresponding to a SCuBA baseline policy (e.g., because the setting hasn't been changed within the past 6 months), ScubaGoggles will indicate that the setting needs to be checked manually. See [Limitations](/docs/usage/Limitations.md) for more details.

## Not Authorized to Access This Resource

If an authorization error similar to the one below appears:
```
/Users/scubagoggles/provider.py:463: RuntimeWarning: An exception was thrown trying to get the tenant info:
<HttpError 403 when requesting https://admin.googleapis.com/admin/directory/v1/customers/my_customer?alt=json returned "Not Authorized to access this resource/api">
```
Ensure that you consented to the following API scopes as a user with the proper [permissions to consent](/docs/prerequisites/Prerequisites.md#permissions) and have enabled the required [APIs and Services](/docs/authentication/OAuth.md).

## Scubagoggles Not Found
If an error similar to the one below appears:
```
command not found: scubagoggles
```

Ensure that you have properly [configured the virtual environment](/docs/installation/DownloadAndInstall.md#installing-in-a-virtual-environment) and have activated the virtual environment using the OS appropriate commands.

Alternatively, to run scubagoggles without installing it as a package, you can replace the `scubagoggles` command with `python scuba.py`.


## Unable to view HTML report due to environment limitations

If you are unable to view the HTML report in a browser window, the results of the conformance scan can be viewed in their raw JSON format.

We recommend running the conformance report in quiet mode to stop the web browser from being opened automatically. This can be done with the `--quiet` parameter:

```scubagoggles gws --quiet```

Once the scan is complete, navigate to the output folder. Within the output folder, we can access the generated HTML reports, or view the results in JSON format.

To view the results as JSON, open the `ScubaResults.json` file.

The output will resemble the following:
```
{
    "Summary": {
      "Gmail": {
          "Manual": 26,
          "Passes": 9,
          "Errors": 0,
          "Failures": 6,
          "Warnings": 2
      },
      "Groups for Business": {
          "Manual": 0,
          "Passes": 6,
          "Errors": 0,
          "Failures": 0,
          "Warnings": 1
      }
    },
    "Results": {
      "Gmail": [
        {
            "GroupName": "Mail Delegation",
            "GroupNumber": "1",
            "Controls": [
                {
                  "Control ID": "GWS.GMAIL.1.1v0.2",
                  "Requirement": "Mail Delegation SHOULD be disabled.",
                  "Result": "Pass",
                  "Criticality": "Should",
                  "Details": "Requirement met in all OUs and groups."
                }
                ...
```

## Navigation
- Return to [Documentation Home](/README.md)
