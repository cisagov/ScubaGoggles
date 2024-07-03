# Write up on Chat 5.1

[Link to my discussion and recommendations after the background section](#discussion)

## Current language for each policy
### Chat 5.1v0.2
User-level ability to install Chat apps SHALL be disabled.

- [Chat 5.1 SCuBA Policy Link](https://github.com/cisagov/ScubaGoggles/blob/v0.2.0/baselines/Google%20Chat%20Minimum%20Viable%20Secure%20Configuration%20Baseline%20v0.2.md#gwschat51v02)
- [Chat 5.1 Google setting documentation](https://support.google.com/a/answer/7651360?product_name=UnuFlow&hl=en&visit_id=637916846359382524-3147840186&rd=1&src=supportwidget0&hl=en#zippy=%2Cstep-add-marketplace-apps-to-your-allowlist-optional%2Cstep-decide-what-apps-users-can-install%2Cstep-let-users-install-apps-in-chat)

### Common Controls 11.1v0.2
Only approved Google Workspace Marketplace applications SHOULD be allowed for installation.

- [Common Controls 11.1 SCuBA Policy Link](https://github.com/cisagov/ScubaGoggles/blob/v0.2.0/baselines/Common%20Controls%20Minimum%20Viable%20Secure%20Configuration%20Baseline%20v0.2.md#11-authorized-google-marketplace-apps)
- [Common Controls 11.1 Google setting documentation](https://support.google.com/a/answer/6089179?fl=1)

## Background 

In the Google documentation for Chat 5.1 there is this line.

<img src="images/chatdocumentation.png">

The takeaway of this line was that if the setting for Chat 5.1 is `disabled` then users and admins would not be able install any chat app.

From [Jonathan's notes](https://github.com/cisagov/ScubaGoggles/issues/222#issuecomment-2037786328) 
- If the new feature is turned on, but the app IS NOT allowlisted, then only admins are allowed to install the app for the org.
- If the feature is turned on and the app IS allowlisted, then both admins and users can install.
- If the new feature is off, then the app cannot be installed.

Below is confirmation of the notes above, using the Zoom app for Google Chat as an example.

### Scenario 1
- If Chat 5.1 is `enabled`
- If Common Controls 11.1 is `enabled for allowlisting`
- The `app is not allowlisted`. 
The below screenshot appears happens when trying to install the Zoom app.

<img src="images/Chat 5.1 is enabled and CC 11.1 is enabled for allowlisting with the app not allowlist.png">
> Note that the option for individual users to install this chat app is grayed out.

### Scenario 2
- If Chat 5.1 is `enabled`
- If Common Controls 11.1 is `enabled for allowlisting`
- The `app is Allowlisted`. 
The below screenshot appears happens when trying to install the Zoom app.
<img src="images/Chat 5.1 is enabled and CC 11.1 is configured for allowlists and the app is allowlisted.png">
> Note that the option for both admins and users to install this chat app is available.

### Scenario 3
- If Chat 5.1 is `disabled`
- If Common Controls 11.1 is `enabled for any app to be installed`
- `Any app is able to be installed`. 
<img src="images/Chat 5.1 is disabled but CC 11.1 is enabled with any app able to be installed without allowlist.png">
> Note that both options to install this chat app are grayed out.

### Scenario 4
- If Chat 5.1 is `enabled`
- If Common Controls 11.1 is set to `disallows any application from being installed`
- `All applications are disallowed`. 
<img src="images/Chat 5.1 is enabled but CC11 restricts any app from being enabled.png">
> Note that the `+` option to install apps in google chat `disappears` altogether


In the next image below, the option to install apps reappears, when common controls 11.1 is set to `any setting other than disallowing installation of apps`.
<img src="images/Common Controls 11.1 is enabled in any form.png">
> Note that the `+` option to install apps in google chat `reappears`

### Scenario 5
- If Chat 5.1 is `disabled`
- If Common Controls 11.1 is `enabled for allowlisting`
- The `app is Allowlisted`. 
<img src="images/Chat 5.1 is disabled but CC 11.1 is enabled but the app is allowlisted.png">
> Note that both options are still grayed out even with the app allowlisted in common controls 11.1

## Discussion
- If Chat 5.1 is enabled then Common Controls 11.1 settings do apply to chat apps.
- If Chat 5.1 is disabled ten Common Controls 11.1 settings do not matter.
- If Common Controls 11.1 disallows installation of all apps then it prevents any app from being installed. 

From the findings above, Common Controls 11.1 appears to be the finer grained controls in contrast to Chat 5.1.
Chat 5.1 is an all or nothing setting. 
Where users can install Chat apps if Chat 5.1 is enabled or not at all if the setting is disabled. Including administrators. 

- Depending on agency/organizational risk posture they may want to disable Chat 5.1 altogether.
- Or they might enable Chat 5.1 with allowlisting enforced by Common Controls 11.1.
- Or they might disable installation of apps altogether via Common Controls 11.1 which makes any Chat 5.1 setting configuration ineffectual. 

SCuBA tries to balance the fine line between mandating a security configuration be implemented and allowing for agencies/organizations flexibility for operational needs. 

"Chat 5.1 does not offer the allowlisting flexiblity for controlling applications that Common Controls 11.1 offers. Thus, I would recommend cutting Chat 5.1 and leaving the decision of the configuration of that setting up to agencies/organizations." - David Bui
