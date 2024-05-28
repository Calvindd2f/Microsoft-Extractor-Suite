.. image:: /Images/Invictus-Incident-Response.jpg
   :alt: Invictus logo

# Microsoft-Extractor-Suite Documentation

**Microsoft-Extractor-Suite** is a fully-featured, actively-maintained PowerShell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.

For incident response support, please reach out to cert@invictus-ir.com or go to <https://www.invictus-ir.com/247>.

## Supported Sources

===================================== =========================================================================================================================================================================== 
Source                                Description                                                                                                                                                                
===================================== =================================================================================================================------------------------------------------------========== 
Unified Audit Log                     The unified audit log contains user, group, application, domain, and directory activities performed in the Microsoft 365 admin center or in the Azure management portal.   
Admin Audit Log                       Administrator audit logging records when a user or administrator makes a change in your organization (in the Exchange admin center or by using cmdlets).                   
Mailbox Audit Log                     Mailbox audit logs are generated for each mailbox that has mailbox audit logging enabled. This tracks all user actions on any items in a mailbox.                          
Message Trace Log                     The message tracking log contains messages as they pass through the organization.                                                                                          
OAuth Permissions                     OAuth is a way of authorizing third-party applications to login into user accounts.                                                                                        
Inbox Rules                           Inbox rules process messages in the inbox based on conditions and take actions such as moving a message to a specified folder or deleting a message.                       
Transport Rules                       Transport rules take action on messages while they're in transit.                                                                                                          
Azure Active Directory sign-in log    Gets the Azure Active Directory sign-in log.                                                                                                                               
Azure Active Directory Audit Log      Gets the Azure Active Directory audit log.  
Azure Activity Log                    Gets the Azure Activity log.                                                                                                           
===================================== =================================================================================================================------------------------------------------------========== 

## Retrieve Other Relevant Information

===================================== =========================================================================================================================================================================== 
Source                                Description                                                                                                                                                                
===================================== =================================================================================================----------------------------------------------------------------========== 
MFA                                   Retrieves the MFA status for all users.                                                                                                                                   
User information                      Retrieves the creation time and date of the last password change for all users.                                                                                                
Risky users                           Retrieves the risky users.                                                                                                                                                 
Risky Detections                      Retrieves the risky detections from the Entra ID Identity Protection.                                                                                                      
Conditional Access Policies           Retrieves all the conditional access policies.                                                                                                                                
Admin users/roles                     Retrieves Administrator directory roles, including the identification of users associated with each specific role.                                                                
E-mails                               Get a specific email.                                                                                                                                                         
Attachments                           Get a specific attachment.                                                                                                                                                                                                                                          
===================================== =================================================================================================----------------------------------------------------------------========== 

## Getting Started

To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met. If you do not have the **Connect-ExchangeOnline** or/and **Connect-AzureAD** installed, check the installation page.

Install the Microsoft-Extractor-Suite toolkit:




To import the Microsoft-Extractor-Suite:




Additionally, you must sign-in to Microsoft 365 or Azure depending on your usage before M365-Toolkit functions are made available. To sign in, use the cmdlets:




## Getting Help

Have a bug report or feature request? Open an issue on the Github repository.



