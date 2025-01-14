
# Configuring Defaults
There are several options that users can configure ScubaGoggles to use by default, including:
- The location of the OPA executable
- The location for saving ScubaGoggles output
- The location of the user's credentials file

The provided `setup` utility is the mechanism of specifying these default values.

## OPA location
See [Download the OPA Executable](/docs/installation/OPA.md) for instructions on obtaining the OPA executable. If the
user used the `setup` utility for the initial OPA download, no further configuration is necessary. If the user
downloaded the executable manually or for whatever reason desires to change the default OPA path, use the following
command:
```
scubagoggles setup --opapath [path to executable]
```

## ScubaGoggles Output
Unless configured otherwise, the default location for ScubaGoggles output is the current working directory of the user
invoking ScubaGoggles. This default can be changed using the following command:
```
scubagoggles setup --outputpath [path to output directory]
```

## User Credentials
ScubaGoggles leverages credentials stored in a JSON file to authenticate to Google's APIs. After creating this JSON file
(see [Prerequisites](../prerequisites/Prerequisites.md) and [Authentication Methods](/docs/authentication/AuthenticationMethods.md)), the `setup` utility can be used to indicate the credentials file the should be used by default:
```
scubagoggles setup --credentials [path to JSON credentials file]
```

> [!NOTE]
> All of the above options can be run at any time, jointly or on their own, whenever the default values need to be changed.

## Navigation
- Continue to [Prerequisites](../prerequisites/Prerequisites.md)
- Return to [Documentation Home](/README.md)
