Step 3: Tenant Permissions
You will see a list of necessary permissions for Microsoft Exchange Online, which typically includes:

Exchange.Manage: Manage general features and settings.

Exchange.ManageAsApp: Manage Exchange features at the app level.

Full_Access_As_App: Grant full access to the app to manage Exchange.

Click Next to proceed to Step 4

For more information on Exchange PermissionsMicrosoft Exchange Online Permissions section of the Microsoft Cloud permissions page

Troubleshooting Tips
Authorization Issues: If you encounter problems during the authorization step, ensure that you are using the correct account and that all permissions are properly set.

Permission Configuration Errors: Double-check the permissions if there are issues with accessing certain functionalities. Ensure that the appropriate permissions are enabled and correctly configured.

For troubleshooting tips, check out the Troubleshooting installation issues and Common issues with the Microsoft Cloud integration bundle pages.

Best Practices for Microsoft Integrations
For best practice information please refer to: Best Practices for Microsoft Integrations.

Actions
Invoke Command
Invoke a command in Microsoft Exchange Online (EXO).

Name
Type
Description
Cmdlet Name

String

Required. The name of the cmdlet to run.

Parameters

Array[[Parameter](#parameter)]

Required. The parameters to pass to the cmdlet.

Remove Empty

boolean

If true, any null value will be stripped before sending the request. Default: true.

Anchor Mailbox

Exchange Online and multi-property values
Many people are familiar with the Exchange Online Management Powershell module and how cmdlets/parameters are structured. There are some differences in how the module sends its commands/parameters and how the Exchange Admin API does them.

One key example is when people grant send on behalf permissions.

Here's an example of a Powershell Command:

Set-Mailbox -Identity seanc@contoso.com -GrantSendOnBehalfTo pedro

This will set the SendOnBehalf permission for the mailbox seanc to be the user pedro. However, in some scenarios, it is necessary to grant multiple people access to the mailbox. Re-running the same command above will overwrite existing values, it is generally a better idea to pass it as a multi-property value.

Here's an example:

Set-Mailbox -Identity "seanc@contoso.com" -GrantSendOnBehalfTo @{Add="pedro@contoso.com"}

This will append the new permission instead of overwriting it. Doing this in Rewst is a little bit different because the Exchange Admin API expects certain formatting in the request when it is sent to the API and you are providing a multi-value property.

Steps to perform the same action in Rewst:
Add your InvokeCommand action to your workflow.

For the cmdlet set the value to: Set-Mailbox

Add an Identity parameter with the target mailbox

Add a GrantSendOnBehalfTo parameter and give it a value similar to
