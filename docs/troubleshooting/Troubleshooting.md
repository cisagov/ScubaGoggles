# Troubleshooting

## Not Authorized to Access This Resource

If an authorization error similar to the one below appears:

```
RuntimeWarning: An exception was thrown trying to get the tenant data:
<HttpError 403 ... returned "Not Authorized to access this resource/api">
```
Ensure that you consented to the following API scopes as a user with the proper
[permissions to consent](../prerequisites/Prerequisites.md#permissions) and have
enabled the required [APIs and Services](../authentication/OAuth.md).

## macOS: Certificate Verification Error

If you are installing ScubaGoggles on a system running macOS, you may
encounter a "certificate verification error" while ScubaGoggles is attempting
to download the OPA executable (either via the `setup` or `getopa` commands).
The **secure** HTTP protocol (https) is used when downloading the OPA
executable.  If the certificate provided by `openpolicyagent.org` can't be
verified on your local system, you will encounter this error.

This issue may be due to Python on macOS providing its own copy of OpenSSL.
Because of this, the trust certificates typically used for certificate
verification on your system are not used by Python.

The following steps may help you to resolve this issue.

* Instead of using ScubaGoggles to download the OPA executable, you may
download OPA using a browser.  Remember to locate the executable where
ScubaGoggles expects to find it and make sure the file has *execute*
permission ([see installation instructions](
    ../installation/OPA.md#download-the-opa-executable)).

* Depending on the method you used to install Python, the installation may be
located in `/Applications/Python <version>`, for example
`/Applications/Python 3.13`.  If that directory exists, you should find a
file named `install_certificates.command`.  Running this file will install
the trust certificates and should fix the issue.

* If the file mentioned in the step above does not exist on your system,
you may find this file at the [cPython GitHub site](
    https://github.com/python/cpython).  You will find the script in the
[`Mac/BuildScript/resources`](
    https://github.com/python/cpython/tree/main/Mac/BuildScript/resources)
folder.  The [`ReadMe.rtf`](
    https://github.com/python/cpython/tree/main/Mac/BuildScript/resources/ReadMe.rtf) file will provide more information about getting
certificate verification to work correctly on your macOS system.

## Windows:  WinError 10013: Permission Error

When ScubaGoggles is run and it needs to re-authorize you using your Google
credentials, it makes a connection using port 8080.  If you receive a permission
error with the text `An attempt was made to access a socket in a way forbidden
by its access permissions`, it is likely that another process on your system is
using that port.

The following PowerShell command, when run as an Adminstrator, may help to
locate the process using the port.  Once you've determined how the port is
being used, you can evaluate whether something may be done to temporarily
relinquish the port for ScubaGoggles use or whether you might need to try
running ScubaGoggles on a system where the port is available.

```
Get-Process -Id (Get-NetTCPConnection -LocalPort 8080).OwningProcess
```

## Unable to view HTML report due to environment limitations

If you are unable to view the HTML report in a browser window, the results of
the conformance scan can be viewed in their raw JSON format.

We recommend running the conformance report in quiet mode to stop the web
browser from being opened automatically. This can be done with the `--quiet`
parameter:

```scubagoggles gws --quiet```

Once the scan is complete, navigate to the output folder. Within the output
folder, you can access the generated HTML reports, or view the results in JSON
format.

To view the results as JSON, open the `ScubaResults.json` file.

The output will resemble the following:

```json
{
    "Summary": {
        "sites": {
            "Manual": 0,
            "Passes": 1,
            "Errors": 0,
            "Failures": 0,
            "Warnings": 0,
            "Omit": 0
        }
    },
    "Results": {
        "sites": [
            {
                "GroupName": "Sites Service Status",
                "GroupNumber": "1",
                "GroupReferenceURL": "https://github.com/cisagov...",
                "Controls": [
                    {
                        "Control ID": "GWS.SITES.1.1",
                        "Requirement": "Sites Service SHOULD be disabled for all users.",
                        "Result": "Pass",
                        "Criticality": "Should",
                        "Details": "Requirement met in all OUs and groups."
                    }
                ]
            }
        ]
    },
```

## ScubaGoggles lists failures for the SPF, DKIM, and DMARC policies (GWS.GMAIL.2 through GWS.GMAIL.4) even though you have published the applicable DNS records

### Most common cause
ScubaGoggles uses the system-default DNS resolver to resolve the SPF, DKIM, and DMARC records, so its visibility is only
as good as your default DNS resolver’s visibility. One issue users sometimes run into is something called split-horizon
DNS, where a DNS request made from inside the network returns different results than one made from outside the
network. In cases such as this, ScubaGoggles might report failures for the above policies because the DNS resolver did
not return the SPF, DKIM, or DMARC records.

### Diagnosing the issue
ScubaGoggles appends logs of all DNS queries made to the end of the Gmail baseline report. Review the answers
ScubaGoggles received, are they different than expected? When split-horizon is at play, the DNS resolvers often return
no answer or NXDOMAIN, though that is entirely dependent on your network setup. Compare the answers received with those
returned by a public lookup tool. If they differ, then ScubaGoggles is impacted by split-horizon DNS.

### Resolving the issue
ScubaGoggles includes the `preferreddnsresolvers` commandline argument, which allows users to specify which DNS
resolvers should be used to retrieve the DNS records ScubaGoggles needs. If the system-default resolver is unable to
retrieve the SPF, DKIM, or DMARC records, the user can provide the IP address of one that can, such as a public DNS
resolver. For example: `scubagoggles gws --preferreddnsresolvers 8.8.8.8 8.8.4.4`. Note however, that some systems block DNS queries to DNS resolvers that are not approved for use on the system. If that is the case, ScubaGoggles will not be able to resolve the DNS queries unless the user provides a DNS resolver that is approved for use on their network.

## Navigation
- Return to [Documentation Home](/README.md)
