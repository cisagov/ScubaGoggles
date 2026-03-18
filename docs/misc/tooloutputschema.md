![SScubaGoggles Logo](../images/ScubaGoggles%20GitHub%20Graphic%20v2.jpg)

## Object Schema for ScubaGoggles Output JSON

This document is intended to be an authoritative source of the object schema JSON from ScubaGoggles.

<details>
<summary>Overview</summary>

| Field Name | Type | Description | Location on HTML report | Example |
| --- | --- | --- | --- | --- |
| MetaData | Object | Contains contextual information about the data in the current SCuBA tool output JSON file. | N/A| N/A|
| MetaData.TenantId | String | A unique identifier assigned to each M365 tenant/GWS customer. | On the report summary page under "Tenant ID" (ScubaGear only). | 32c412d2-b044-3425-8ed1-ab220b70d3d1 |
| MetaData.DisplayName | String | The display name of the M365 tenant/GWS customer. | On both the report summary page and the individual report for each baseline under "Tenant Display Name" (ScubaGear only). | Example Tenant Name |
| MetaData.DomainName | String | The primary domain of the customer (ScubaGoggles) or the initial and immutable .onmicrosoft.com domain of an Entra ID tenant (ScubaGear). | On the report summary page under "Customer Domain" (ScubaGoggles) or "Tenant Domain Name" (ScubaGear). | example.com |
| MetaData.ProductSuite | String | Name of the SCuBA baseline product suite that is being assessed with the current SCuBA tool. | N/A| Google Workspace |
| MetaData.ProductsAssessed | Array | List of products scanned by the SCuBA tool. | On the report summary page, the values in the "Baseline Conformance Reports" column. | ["Common Controls", "Gmail"] |
| MetaData.ProductAbbreviationMapping | Object | A mapping of the list of products assessed during a run of the SCuBA tool to the abbreviations used in the policy identifiers and policy groups in the SCuBA secure configuration baseline documents. | N/A| {"Common Controls", "Gmail"} |
| MetaData.Tool | String | Name of the current SCuBA tool conducting the assessment. | On the footer of the report summary page, e.g., "Report generated with CISA's ScubaGoggles tool v0.6.0." | ScubaGoggles |
| MetaData.ToolVersion | String | Version of the current SCuBA tool conducting the assessment. | On the footer of the report summary page, e.g., "Report generated with CISA's ScubaGear tool v1.7.1." | 1.7.1 |
| MetaData.TimestampZulu | String | ISO 8601 compliant timestamp at zero offset from Coordinated Universal Time (UTC). | N/A, though a timestamp formatted in the local datetime of the user that ran the tool is shown on both the report summary page and the individual report for each baseline under "Report Date." | 2024-03-20T18:42:05.043Z |
| MetaData.ReportUUID | String | UUIDv4 128-bit label used to uniquely identify a SCuBA tool assessment result. | In the bottom right of the footer of the report summary page, eg., "Report UUID: 516d34ab-8d53-4862-979a-a3ff11b4abb6" | 516d34ab-8d53-4862-979a-a3ff11b4abb6 |
| MetaData.RunType | String | The run type, either "scheduled" or "ad-hoc". This data is not native to ScubaGear/ScubaGoggles but is inserted by ScubaConnect during processing. | N/A| scheduled |
| AnnotatedFailedPolicies | Object | Collection of failed SHALL policies along with any annotations for those policies the user included in their config file. Maps control IDs to '<AnnotationObject>' objects. See the "Annotation Object" tab of this spreadsheet for more details. | Annotations are appended to the "Details" column. | "AnnotatedFailedPolicies": {"MS.EXO.4.2v1": {"Comment": "We're failing because reasons, we will fix soon.", "RemediationDate": "2024-08-01", "IncorrectResult": false}} |
| Summary | Object | Map of product names to numerical summaries of the assessment results for each SCuBA product (`<SummaryObject>` objects). See the "Summary Object" tab of this spreadsheet for more details. The specific keys included under the Summary key are the short forms of the names of the products assessed (see both MetaData.ProductsAssessed and MetaData.ProductAbbreviationMapping). | N/A| "Results": {"gmail": `<SummaryObject>`, "calendar": `<SummaryObject>`} |
| Results | Object | Map of product names to the assessment results for each SCuBA product (arrays of `<ResultsObject>` objects). See the "Results Object" tab of this spreadsheet for more details. The specific keys included under the Summary key are the short forms of the names of the products assessed (see both MetaData.ProductsAssessed and MetaData.ProductAbbreviationMapping). | On each individual HTML report page. The policy group numbers, policy names and the html tables containing the assessment results. | "Results": {"gmail": [`<ResultsObject>`, `<ResultsObject>`], "calendar": [`<ResultsObject>`]} |
| Raw | Object | The raw JSON output of a ScubaGear assessment. This contains the data returned by the various API calls used by ScubaGear/Goggles to conduct a conformance assessment of the tenant's configuration against SCuBA's Security Configuration Baseline policies. This is the original ProviderSettingsExport.json file found from a normal ScubaGear run. Values under this field may or may not be present, depending on which products were included in an assessment for a given execution of ScubaGear/ScubaGoggles. | N/A| N/A|
| Raw.baseline_version | String | Soon to be deprecated in favor of individual version numbers for each SCuBA Product Baseline. This represents the current version number SCuBA M365 Secure Configuration Baseline documents. | On each individual report page in in first metadata table. | 1 |
| Raw.date | String | The local date and time of the client that ran a ScubaGear assessment. | On the report home and individual report pages under "Report Date" | 03/20/2024 18:37:26 Pacific Daylight Time |
| Raw.timestamp_zulu | String | ISO 8601 compliant timestamp at zero offset from Coordinated Universal Time (UTC). | N/A, though a timestamp formatted in the local datetime of the user that ran the tool is shown on both the report summary page and the individual report for each baseline under "Report Date." | 2024-03-20T18:42:05.043Z |
| Raw.report_uuid | String | UUIDv4 128-bit label used to uniquely identify a SCuBA tool assessment result. | In the bottom right of the footer of the report summary page, eg., "Report UUID: 516d34ab-8d53-4862-979a-a3ff11b4abb6" | 516d34ab-8d53-4862-979a-a3ff11b4abb6 |
| Raw.tenant_details | Array | Contains tenant metadata information.This field is a result of a PowerShell cmdlet call. Which PowerShell cmdlet this data is taken from depends on which products the ScubaGear user specified to assess. If Azure AD/Entra ID is one of the products assessed then this data is the data by default is the JSON stringified version of the Microsoft Graph Beta Get-MgBetaOrganization PowerShell cmdlet. | On the report home page under Tenant ID, Tenant Display Name, and Tenant Domain Name | See the BaselineReports.html file in the sample-report folder in the ScubaGear GitHub repository https://github.com/cisagov/ScubaGear for an up to date example. |
| Raw.scuba_config | Object | Tenant | N/A| Look for this JSON key (without the Raw top level key) in the ProviderSettingsExport.json file in the sample-report folder in the ScubaGear GitHub repository https://github.com/cisagov/ScubaGear for an up to date example. |
| Raw.scuba_config.OrgName | String | This is an attribute that an organization or federal agency inserts into their config file to specify their parent organization/agency name | N/A| OGA |
| Raw.scuba_config.OrgUnitName | String | This is an attribute that an organization or federal agency inserts into their config file to specify their sub organizational/subagency name | N/A| OGAHQ |
| Raw.spf_records | Array | A list with a DNS Result object generated when querying for the SPF records for each domain associated with the tenant. | N/A| See the "DNS Result Object" tab of this spreadsheet for an example. |
| Raw.dkim_config | Array | The JSON stringified result from the invocation of the Get-DkimSigningConfig PowerShell cmdlet in the Exchange Online PowerShell module. | N/A| Look for this JSON key (without the Raw top level key) in the ProviderSettingsExport.json file in the sample-report folder in the ScubaGear GitHub repository https://github.com/cisagov/ScubaGear for an up to date example. |
| Raw.dkim_records | Array | A list with a DNS Result object generated when querying for the SPF records for each domain associated with the tenant. | N/A| See the "DNS Result Object" tab of this spreadsheet for an example. |
| Raw.dmarc_records | Array | A list with a DNS Result object generated when querying for the SPF records for each domain associated with the tenant. | N/A| See the "DNS Result Object" tab of this spreadsheet for an example. |
| Raw.policies | Object | Map of OU/groups to setting names and values, as returned by the Google Workspace policy API. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.organizational_units | Object | The raw data returned by the `directory/v1/orgunits/list` API call. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.organizational_unit_names | Array | The names of the OUs returned by the `directory/v1/orgunits/list` API call. | N/A | `["Example 1", "Example 2"]` |
| Raw.break_glass_accounts | Array | List of the email addresses of the accounts the user listed as break glass accounts. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.missing_policies | Array | List of any settings from the policy API that are unexpectedly missing. | The details column will list any settings that a given test depends on that are missing from the API output. | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.gmail_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Gmail. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.calendar_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Calendar. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.chat_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Chat. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.classroom_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Classroom. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.commoncontrols_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Common Controls. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.drive_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Drive. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.groups_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Groups. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.meet_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Meet. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.sites_logs | Object | The events returned by the `reports/v1/activities/list` API call that are relevant to Sites. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.tenant_info | Object | The GWS instance’s ID, primary domain name, and top-level OU name. | The domain name is displayed at the top of the reports under “Customer Domain.” The top-level OU is displayed in the “Details” column for controls that were not able to be evaluated due to a lack of data. | `"tenant_info": { "ID": "awoiefjeof", "domain": "example.com", "topLevelOU": "Example" }` |
| Raw.domains | Array | The domain names returned by the `directory/v1/domains/list` API call. | N/A | `["example1.com", "example2.com"]` |
| Raw.successful_calls | Array | The list of API calls that were successful. | N/A | `["get_dmarc_records", "get_spf_records", "get_dkim_records", "directory/v1/domains/list"]` |
| Raw.unsuccessful_calls | Array | The list of API calls that were unsuccessful. | For any given control that was unable to be evaluated due to a failed API call, the failed call will be listed under the “Details” column. | `["get_dmarc_records"]` |
| Raw.super_admins | Array | The list of super admins in the GWS instance. | In the details column for `GWS.COMMONCONTROLS.6.2v0.2`. | `[{"primaryEmail":"example1@example.com","orgUnitPath":""}]` |
| Raw.groups_settings | Array | Output of the `groups-settings/v1/groups/get` API call. | N/A | Look for this JSON key in the `ScubaResults.json` file in the sample-report folder in the ScubaGoggles GitHub repository. |
| Raw.rules_table | Array | An array of `<RuleObject>` objects (one for each rule required by `GWS.COMMONCONTROLS.13.1v1`). | Table appended to the Common Controls report. | See the “Rule Object” section. |
</details>

<details>
<summary>Summary Object</summary>

| Field Name | Type | Description | Example |
| --- | --- | --- | --- |
| Manual | Int | The number of manual checks needed for the baseline (e.g., controls that were not able to be assessed automatically). | 5 |
| Passes | Int | The number of controls that passed for the baseline. | 8 |
| Errors | Int | The number of controls that were unable to be evaluated due to an error during ScubaGear execution. | 0 |
| Failures | Int | The number of controls that failed that were marked as a "SHALL" requirement. | 15 |
| Warnings | Int | The number of controls that failed that were marked as a "SHOULD" requirement. | 3 |
| Omit | Int | The number of controls that were omitted from evaluation via the config file. | 3 |
| IncorrectResult | Int | The number of control results the user marked as incorrect in their config file. | 1 |

</details>

<details>
<summary>Annotation Object</summary>

| Field Name | Type | Description | Example |
| --- | --- | --- | --- |
| Comment | String | User provided comment to provide context, justification, or plan of action for a result. Optional, will be null if not provided. | We're failing because xyz, we will fix soon. |
| RemediationDate | String | The date by which the control will be implemented. Expected in yyyy-mm-dd format. Optional, will be null if not provided. | 2024-08-01 |
| IncorrectResult | Boolean | Whether or not the user considers the result determined by the SCuBA tool to be incorrect. | False |

</details>

<details>
<summary>Results Object</summary>

| Field Name | Type | Description | Example |
| --- | --- | --- | --- |
| GroupName | String | The name of a Policy Control Group from a SCuBA Secure Configuration Baseline (SCB) | App Management |
| GroupNumber | String | The Policy Control Group Number of a SCuBA Secure Configruation Baseline | 5 |
| GroupReferenceURL | String | URL to the markdown anchor in GitHub for the control group. | https://github.com/cisagov/ScubaGear/blob/v1.2.0/PowerShell/ScubaGear/baselines/teams.md#5-app-management |
| Controls | Array | An array of `<ControlObject>` objects with each object containing a SCuBA Policy control's assessment results | See the "Control Object" tab of this spreadsheet for more details. |

</details>

<details>
<summary>Control Object</summary>

| Field Name | Type | Description | Example | Notes |
| --- | --- | --- | --- | --- |
| Control ID | String | The unique identifier string of a policy in a SCuBA Secure Configuration Baseline Document. The first block stands for the overall product i.e MS. The second block stands for the specific product. The 3rd block stand for the policy group number. The 4th block stands for the number of the policy within a policy group and the version v#. Stands for the current version of the policy. ex. MS.EXO.4.2v1 The Microsoft 365 Exchange Online baseline Policy Group 4 Policy 2 version 1 | MS.TEAMS.5.1v1 | N/A|
| Requirement | String | The SCuBA Secure Configuration Baseline document policy text that dictates to the user how a setting in a product is to be configured. | Agencies SHOULD only allow installation of Microsoft apps approved by the agency. | N/A|
| Result | String | The decision made by the ScubaGear assessment whether the tenant ScubaGear was run against meets required configuration stated by the policy. | Warning | Possible values include:<ul><li><code>Pass</code></li><li><code>Fail</code></li><li><code>Warning</code></li><li><code>N/A</code> (typically indicates a manual check needed)</li><li><code>Omitted</code></li><li><code>Incorrect Result</code></li><li><code>Error - Test results missing</code></li><li><code>Error</code></li><li><code>No events found</code> (this is a ScubaGoggles only item and should eventually disappear someday)</li></ul> |
| Criticality | String | Based RFC 2119. SHALL means the policy is required, SHOULD means the policy is recommend,  3rd Party means that the policy may be implemented via a 3rd Party service (e.g., malware protections are required don't have to be done via Defender). | Should | Possible values include:<ul><li><code>Shall</code></li><li><code>Should</code></li><li><code>Shall/3rd Party</code></li><li><code>Should/3rd Party</code></li><li><code>Shall/Not-implemented</code></li><li><code>Should/Not-implemented</code></li></ul> |
| Details | String | The exact information of either how the tenant ScubaGear is run against either does or does not meet the SCuBA Secure Configuration Baseline Policy Requirement | 1 meeting policy(ies) found that does not restrict installation of Microsoft Apps by default: Global | Any annotations will be included in HTML formatted string |
| OriginalResult | String | The raw result before being annotated or omitted. | Warning | N/A|
| OriginalDetails | String | The raw result details before being annotated or omitted. | 1 meeting policy(ies) found that does not restrict installation of Microsoft Apps by default: Global | N/A|
| Comments | Array | Will have annotation and/or omission comments for a control | "We are working on remediating this policy", "Policy is failing for x reason", etc | N/A|
| ResolutionDate | String or null | Will be either remediation date or omission expiration date; if configured both omission date and a remediation date, the omission date takes precedence; if configured neither, this will be null | 2024-08-01 | N/A|

</details>

<details>
<summary>DNS Result Object</summary>

| Field Name | Type | Description | Example |
| --- | --- | --- | --- |
| domain | String | The domain name. | example.onmicrosoft.com |
| rdata | Array | An array of strings represeting the answers returned from the DNS query. | ["v=spf1 include:spf.protection.outlook.com -all"] |
| log | Array | An array of DNS Log Objects with additional data about the results of the DNS query. | See the "DNS Log Object" tab of this spreadsheet for an example. |

</details>

<details>
<summary>DNS Log Object</summary>

| Field Name | Type | Description | Example |
| --- | --- | --- | --- |
| query_method | String | The method used for resolving the DNS query: either "traditional" or "DoH." | traditional |
| query_result | String | String description of the result of the DNS query. | Query returned 1 txt records |
| query_name | String | The domain name. | example.onmicrosoft.com |
| query_answers | String | When the query returned txt recods | "v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov; pct=100; ruf=mailto:reports@dmarc.cyber.dhs.gov"|


</details>

<details>
<summary>Rule Object</summary>

| Field Name | Type | Description | Example |
| --- | --- | --- | --- |
| Alert Name | String | The name of the rule associated with the alert. | New user added |
| Description | String | A brief description of the rule. | A new user has been added to the domain. |
| Status | String | The status of the rule. Either "Unknown", "Enabled", or "Disabled". | Enabled |

</details>
