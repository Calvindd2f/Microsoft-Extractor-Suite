# E-mails and Attachments
========================

This section includes functions for handling e-mails and their attachments using the Microsoft Graph API.

.. note::

    Important note: The following functions require the 'Mail.ReadBasic.All' scope, which is an application-level permission. You need to establish an application-based connection through the 'Connect-MgGraph' command to use this scope.

get-email.ps1
-------------

### Get a specific email

Get a specific email based on user ID and Internet Message ID, and save the output to a .msg or .txt file.

#### Usage

Retrieve an email from user 'fortunahodan@bonacu.onmicrosoft.com' with the Internet Message ID '<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>' to a .msg file.




Retrieve an email and its attachment from 'fortunahodan@bonacu.onmicrosoft.com' with the Internet Message ID '<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>' to a .msg file.




Retrieve an email and save it to the 'C:\Windows\Temp' folder.




#### Parameters

- `-UserIds` (Mandatory): The unique identifier of the user.
- `-InternetMessageId` (Mandatory): The Internet Message ID representing the Internet message identifier of an item.
- `-Output` (optional): The output format (.msg or .txt). Default: .msg
- `-OutputDir` (optional): The output directory. Default: 'EmailExport'
- `-Attachment` (optional): Whether to save the attachment. Default: False

#### Output

The output will be saved to the 'EmailExport' directory within the 'Output' directory.

#### Permissions

Ensure you have the 'Mail.ReadBasic.All' permission before using this function. Connect using the following permission:




get-attachment.ps1
------------------

### Get a specific attachment

Get a specific attachment based on user ID and Internet Message ID, and save the output.

#### Usage

Retrieve the attachment from 'fortunahodan@bonacu.onmicrosoft.com' with the Internet Message ID '<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>'.




Retrieve an attachment and save it to the 'C:\Windows\Temp' folder.




#### Parameters

- `-UserIds` (Mandatory): The unique identifier of the user.
- `-InternetMessageId` (Mandatory): The Internet Message ID representing the Internet message identifier of an item.
- `-OutputDir` (optional): The output directory. Default: 'EmailExport'

#### Output

The output will be saved to the 'EmailExport' directory within the 'Output' directory.

#### Permissions

Ensure you have the 'Mail.ReadBasic.All' permission before using this function. Connect using the following permission:




show-email.ps1
--------------

### Show an email

Show a specific email in the PowerShell Window.

#### Usage

Show a specific email in the PowerShell Window.




#### Parameters

- `-UserIds` (Mandatory): The unique identifier of the user.
- `-InternetMessageId` (Mandatory): The Internet Message ID representing the Internet message identifier of an item.
