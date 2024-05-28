<#
.SYNOPSIS
This script is designed to connect to Office 365 audit logs and export the data to a CSV file.

.DESCRIPTION
The script will connect to the Office 365 audit logs, filter the data based on the provided StartDate and EndDate, and export the results to a CSV file.

.PARAMETER StartDate
Specifies the start date for the audit log search in the format of yyyy-mm-dd.

.PARAMETER EndDate
Specifies the end date for the audit log search in the format of yyyy-mm-dd.

