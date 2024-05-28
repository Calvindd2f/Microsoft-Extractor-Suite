#### Known Errors and Solutions

1. **StartDate is later than EndDate**
    - Ensure that the StartDate you enter is earlier than the EndDate.
   
2. **Audit logging is enabled in the Office 365 environment but no logs are getting displayed?**
    - The user must be assigned an Office 365 E5 license. Alternatively, users with an Office 365 E1 or E3 license can be assigned an Advanced eDiscovery standalone license. Administrators and compliance officers who are assigned to cases and use Advanced eDiscovery to analyze data don't need an E5 license.
   
3. **Invalid Argument "Cannot convert value" to type "System.Int32"**
    - This error is observed on PowerShell on macOS, but it doesn't affect the script's functionality. The script will work fine and continue.
   
4. **Output directory expected**
    - The Output directory, as part of the folder structure from GitHub, is expected to be used for all output. If you attempt to use the script from a location outside of the folder structure provided by the GitHub repository, then errors will be thrown by the script, or the output won't be written to disk.
   
#### Solution

To avoid these errors, follow these guidelines:

- Always enter a StartDate earlier than the EndDate.
- Ensure that the user has the required license to view the audit logs.
- Run the script within the folder structure provided by the GitHub repository.
- Ignore the "Invalid Argument" error if it occurs on macOS.
