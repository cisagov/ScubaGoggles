**NOTE** The following documentation is for ScubaGoggles
developers.

# ScubaGoggles Version

There is only **one** location for the "official" version
number for ScubaGoggles.  The version number resides in the
`scubagoggles/__init__.py`, defined in the `__version__`
variable.

The format of the version number is `<major>.<minor>.<build>`,
where `<major>` is the major version number, `<minor>` is the
minor version number, and `<build>` is the build number.
Each component is an integer.

## The Version class

The version number should be accessed in Python code
by using the `Version` class implemented in
`scubagoggles/version.py`.

These `Version` class attributes are available for accessing the version number:

| Attribute Name | Type    | Description          | Example                 |
|----------------|---------|----------------------|-------------------------|
| current        | string  | 'v' prefixed version | `'v1.0.0' `             |
| number         | string  | version              | `'1.0.0' `              |
| with_name      | string  | product and version  | `'ScubaGoggles v1.0.0'` |
| major          | integer | major version        | `1`                     |
| minor          | integer | minor version        | `0`                     |
| build          | integer | build number         | `0`                     |
| suffix         | string  | baseline version     | `'v1.0'`                |

## Baseline Versioning

Baseline policies in ScubaGoggles are identified by a policy
identifier.  The format of the policy ID is:
`GWS.<app-name>.<policy-number>.v<baseline-version>`.  The
`<app-name>` identifies the Google Workspace application
as shown in the following table:

| <app-name>     | Description         |
|----------------|---------------------|
| CALENDAR       | Calendar            |
| CHAT           | Chat                |
| CLASSROOM      | Classroom           |
| COMMONCONTROLS | Common Controls     |
| DRIVEDOCS      | Drive and Docs      |
| GMAIL          | Gmail               |
| GROUPS         | Groups for Business |
| MEET           | Meet                |
| SITES          | Sites               |

The `<policy-number>` has the format `<section>.<item>`,
where `<section>` is the number of the section in the
baseline for the application and `<item>` is the number of
the specific requirement in the section.

The `<baseline-version>` is derived from the ScubaGoggles
version number: `<major>.<minor>`.

### Policy Identifiers in Markdown

Policy identifiers are used throughout the baseline
Markdown documents.  Because the identifiers contain
the baseline version, the identifiers must be changed
when the ScubaGoggles version number changes (except
for the build number component).

Changes to the policy identifiers due to the ScubaGoggles
version number changing is handled by the
`scubagoggles version` command (the functionality is
implemented in the `Version` class).  There is no
manual editing necessary in the Markdown files when the
ScubaGoggles version number changes.

### Policy Identifiers in Rego Code

Policy identifiers are also used in the Rego code as
string values in variables.  The `PolicyIdWithSuffix`
function, defined in `utils.rego`, is used to avoid the
necessity of making changes to all Rego files when the
ScubaGoggles version number changes.

The `PolicyIdWithSuffix` function takes a single string
argument, which is the policy identifier without the
baseline version.  The function adds the current baseline
version to the end of the string to form the complete
policy identifier.

This is an example of specifying a policy identifier in
the Rego code:

```
PolicyId := utils.PolicyIdWithSuffix("GWS.CALENDAR.1.1")
```

Don't specify the complete policy identifier in comments.
There is no need to include the baseline version in the
identifier if it's necessary to reference a policy in the
comments. Including the baseline version requires a manual change
if the ScubaGoggles version changes and opens the possibility of
forgetting to make the changes.

```
# No version suffix in the policy identifier comment:
# Baseline GWS.CHAT.1.2
#--
```

The `scubagoggles version` command updates the single hard-coded
baseline version number in the `PolicyIdWithSuffix` function definition
in `utils.rego`.

## Upgrading ScubaGoggles Version

Upgrading the ScubaGoggles version is done entirely by running the
`scubagoggles version` command with the `--upgrade` option.  This sets the
new version number and modifies all Markdown files and the `utils.rego` file
to replace the baseline version numbers.

The following example shows a version upgrade to 1.0.0 with debug
logging enabled.  The debug output shows the files read and indicates
any changes by showing the line number and the new content of
the line.

```shell
> scubagoggles -log debug version --upgrade 1.0.0
ScubaGoggles version upgrade (1.0.0)
(INFO): changing ScubaGoggles version to 1.0.0
(DEBUG): C:\scubaDev\scubagoggles\rego\Utils.rego
(DEBUG): C:\scubaDev\scubagoggles\rego\Utils.rego:
(DEBUG):      9) BaseVersionSuffix = "v1.0"
(DEBUG): C:\scubaDev\scubagoggles\baselines\calendar.md
...

```

After the version upgrade, the ScubaGoggles Git repository will indicate
the modified files.  To permanently include the version changes, the
files must be committed to the repository.

```
> git status

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   scubagoggles/__init__.py
        modified:   scubagoggles/baselines/calendar.md
        modified:   scubagoggles/baselines/chat.md
        modified:   scubagoggles/baselines/classroom.md
        modified:   scubagoggles/baselines/commoncontrols.md
        modified:   scubagoggles/baselines/drive.md
        modified:   scubagoggles/baselines/gmail.md
        modified:   scubagoggles/baselines/groups.md
        modified:   scubagoggles/baselines/meet.md
        modified:   scubagoggles/baselines/sites.md
        modified:   scubagoggles/rego/Utils.rego
        ...

> git add --update
> git commit -m 'version upgrade to 1.0.0'
```

## Checking Version Number Consistency

When the `scubagoggles version` command is invoked with the `--check`
option, all Markdown files and the `utils.rego` file are checked for
version numbers consistent with the current ScubaGoggles version number
defined in `scubagoggles/__init__.py`.  If any inconsistencies are found,
the file name and line(s) (with line number(s)) are displayed.

```
> scubagoggles version --check
ScubaGoggles version check
```
