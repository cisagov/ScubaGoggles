
### Unable to view HTML report due to environment limitations 

If you are unable to view the HTML report in a browser window, the results of the conformance scan can be viewed in their raw JSON format. 

We recommend running the conformance report in quiet mode to stop the web browser from being opened automatically. This can be done with the `--quiet` command: 

```scubagoggles gws --quiet```

Once the scan is complete, navigate to the output folder. Within the output folder, we can access the generated HTML reports, or view the results in JSON format. 

To view the JSON, open the `ScubaResults.json` file. 

Each baseline will appear in the following format: 

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