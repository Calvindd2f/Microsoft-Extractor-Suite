# E-mails and Attachments
========================

This section includes functions for handling e-mails and their attachments using the Microsoft Graph API.

.. note::

    Important note: The following functions require the 'Mail.ReadBasic.All' scope, which is an application-level permission. You need to establish an application-based connection through the 'Connect-MgGraph' command to use this scope.

### Function: Get-Email
### Get a specific email

Get-Email -UserIds <String> -InternetMessageId <String> [-Output <String>] [-OutputDir <String>] [-Attachment <SwitchParameter>]

#### Parameters

- `-UserIds` (Mandatory): The unique identifier of the user.
- `-InternetMessageId` (Mandatory): The Internet Message ID representing the Internet message identifier of an item.
- `-Output` (optional): The output format (.msg or .txt). Default: .msg
- `-OutputDir` (optional): The output directory. Default: 'EmailExport'
- `-Attachment` (optional): Whether to save the attachment. Default: False

#### Output

The output will be saved to the specified output directory.

### Function: Get-Attachment
### Get a specific attachment

Get-Attachment -UserIds <String> -InternetMessageId <String> [-OutputDir <String>]

#### Parameters

- `-UserIds` (Mandatory): The unique identifier of the user.
- `-InternetMessageId` (Mandatory): The Internet Message ID representing the Internet message identifier of an item.
- `-OutputDir` (optional): The output directory. Default: 'EmailExport'

#### Output

The output will be saved to the specified output directory.

### Function: Show-Email
### Show an email

Show-Email -UserIds <String> -InternetMessageId <String>

#### Parameters

- `-UserIds` (Mandatory): The unique identifier of the user.
- `-InternetMessageId` (Mandatory): The Internet Message ID representing the Internet message identifier of an item.

