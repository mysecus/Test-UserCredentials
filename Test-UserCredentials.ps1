<#	
	.NOTES
	===========================================================================
	 Created on:   	11/21/2017 1:09 PM
	 Filename:     	Test-UserCredentials.ps1
	===========================================================================
	.DESCRIPTION
		The purpose of this script is to test whether users are using a particular password.
		The script is broken into three primary steps:
			1 - Get a list of all users and their BadPwdCount from each domain controller. If the count is 1 away from max before lockout, the script will skip user and add to final report.
			2 - Attempt a single login for each user to verify if account is using a defined password. 
			3 - If user is validated with defined password, log user's info in the final report.
#>

#Requires -Module ActiveDirectory
Import-Module activedirectory

# ===========================================
#
# Section: Functions
#
# ===========================================

#region function Get-DomainControllers
<# 
Name: Get-DomainControllers
Original Author: Ben Wilkinson
Citation: https://gallery.technet.microsoft.com/scriptcenter/List-Domain-Controllers-in-2bec62a5
#>

function global:Get-DomainControllers
{
	#Requires -Version 2.0             
	[CmdletBinding()]
	Param
	(
		#$Name, 
		#$Server, 
		#$Site, 
		[String]$Domain,
		#$Forest 

		[Switch]$CurrentForest
	) #End Param 
	
	Begin
	{
		
	} #Begin           
	Process
	{
		
		if ($CurrentForest -or $Domain)
		{
			try
			{
				$Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
			}
			catch
			{
				"Cannot connect to current forest."
			}
			if ($Domain)
			{
				# User specified domain OR Match 
				$Forest.domains | Where-Object { $_.Name -eq $Domain } |
				ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }
			}
			else
			{
				# All domains in forest 
				$Forest.domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }
			}
		}
		else
		{
			# Current domain only 
			[system.directoryservices.activedirectory.domain]::GetCurrentDomain() |
			ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }
		}
		
	} #Process 
	End
	{
		
	} #End 
	
}
#endregion


# ===========================================
#
# Section: Variables
#
# ===========================================

#region initialize variables
# Set Domain's lockout threshold
# If unsure run "Get-GPOReport -Guid {UNIQUEID} -ReportType html -Path c:\temp\GPOReport.html"
# If above command doesn't work, check the GUID in Group Policy Management'
$LockoutBadCount = 5

# Max Script BadPwdCount Threshold
# Prevents script from locking out users that are near LockoutBadCount threshold
$MaxLockoutBadCountCheck = $LockoutBadCount - 1

# Get a list of all domain controllers in the forest and setup for next step
$DomainControllers = Get-DomainControllers

# Initialize array for users that will be skipped if BadPwdCount >= MaxLockoutBadCountCheck
$ExcludedUsers = @()

# Initialize array for users that will have their credentials checked
$IncludedUsers = @()

# Initialize array for users that use $CheckedPassword
$FailedUsers = @()

# Prompt for password to test against users
$CheckedPassword = Read-Host -Prompt "Please enter password to test: "

# Get Current logged on user's DisplayName
$LocalUser = (Get-ADUser -Identity $env:USERNAME | select Name).Name

# Get Current Date for $ReportName during export
$Date = Get-Date

# Export Path for reports
$ExportPath = "C:\temp\UserCredentialTest_" + (Get-Date -Format MMddyy)

#endregion

# ===========================================
#
# Section: Script
#
# ===========================================

#region Get BadPwdCount for all users in domain and generate two arrays: $IncludedUsers, $ExcludedUsers
# For each domain controller, get current bad password count for each user.
# Default DC replication is 180 minutes. Instead of only checking current DC, script checks each server to test BadPwdCount in case AD replication hasn't occured yet.
# User could have failed logon attempts before replication occured.
Write-Host "Querying Domain controllers" -ForegroundColor Yellow
Start-Sleep 1

foreach ($DC in $DomainControllers)
{
	try
	{
		Write-Host "Searching users on server: $DC"
		
		# Add each user to the ExcludedUsers Array if MaxLockoutBadCountCheck is reached
		$ExcludedUsers += Get-ADUser -Filter { BadPwdCount -ge $MaxLockoutBadCountCheck } -Property BadPwdCount | Sort-Object BadPwdCount -Descending | select SamAccountName
	}
	catch
	{
		Write-Host "Could not complete task for $DC"
	}
}

# Remove duplicate users from array
$ExcludedUsers = $ExcludedUsers | Sort-Object -Property SamAccountName -Unique

#Get all AD Users and exclude $ExcludedUsers
$IncludedUsers = Get-ADUser -Filter { Enabled -eq $true } | where { $ExcludedUsers.SamAccountName -notcontains $_.SamAccountName }

#endregion

#region Test User Credentials
Write-Host "Testing login for each user" -ForegroundColor Yellow
Start-Sleep 1
# Test user account credentials
foreach ($user in $IncludedUsers)
{
	$username = $user.SamAccountName
	
	# Get current domain using logged-on user's credentials
	$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
	#Test if New-Object can be created using user's credentials. If not, nothing is stored in $domain.
	$domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $username, $CheckedPassword)
	
	if ($domain.name -eq $null)
	{
		#terminate iteration
	}
	else
	{
		write-host "Successfully authenticated with: " $username -ForegroundColor Red
		#Generate list of users containing $CheckedPassword
		$FailedUsers += $user.SamAccountName
	}
}
#endregion

#region Convert string arrays back to PSCustom Objects and gather info
# Convert $FailedUsers from string array to PSCustomObject so that we can query results later to gather additional info
$FailedUsers = $FailedUsers | ForEach{ [PSCustomObject]@{ 'SamAccountName' = $_ } }

# Gather DisplayName, SamAccountName, PasswordLastSet, and Status for each $FailedUsers
$FailedUsers = foreach ($user in $FailedUsers)
{
	Get-ADUser -Identity $user.SamAccountName -Property Enabled, PasswordLastSet | select Name, SamAccountName, PasswordLastSet
}

# Gather DisplayName, SamAccountName, PasswordLastSet, and Status for each $ExcludedUsers
$ExcludedUsers = foreach ($user in $ExcludedUsers)
{
	Get-ADUser -Identity $user.SamAccountName -Property Enabled, PasswordLastSet | select Name, SamAccountName, PasswordLastSet
}


#endregion

# ===========================================
#
# Section: Export Report
#
# ===========================================

# Define Report Fields
$ReportName = "<h1>User Credential Report</h1>"
$ExcludedUsersHeader = "<h2> Skipped Users </h2>"
$FailedUserHeader = "<h2> Users with password: $CheckedPassword </h2>"
$ReportLink = "<br><br><br><br>Path to .csv containing checked users and .htm report: $ExportPath"
$ReportFooter = "<br><br><h3>Report Generated by: $LocalUser on $Date"
$ReportHeader = @'

<style>

<Caption> 

body 
{ 
	background-color:#ffffff;

	font-size:12pt; 
}

h3
{
	font-size:8pt;
}

td, th 
{ 
	border:1px solid black;

	border-collapse:collapse; 
}

th 
{ 
	color:white;

	background-color:LightSlateGray; 
}

table, tr, td, th 
{ 
	padding: 2px; margin: 0px 
}

table 
{ 
	margin-left:50px; 
}

</style>

'@

# Verify if $ExportPath exists. If not, create it. 
if (!(Test-Path -Path $ExportPath))
{
	New-Item -ItemType Directory -Force -Path $ExportPath
}

# Export users that were included in the list to be tested. 
$IncludedUsers | Export-Csv -Path "$ExportPath\IncludedUsers.csv"

# Exports the username of each skipped user to HTML file
$frag1 = $ExcludedUsers | Select-Object Name, SamAccountName, PasswordLastSet | ConvertTo-Html -PreContent $ExcludedUsersHeader | Out-String

# Exports the SamAccountName of users containing $CheckedPassword to HTML file
$frag2 = $FailedUsers | Select-Object Name, SamAccountName, PasswordLastSet | ConvertTo-Html -PreContent $FailedUserHeader | Out-String

# Compile and Export Final Report
ConvertTo-Html -Head $ReportHeader -PostContent $frag1, $frag2, $ReportLink, $ReportFooter -PreContent $ReportName | Out-File "$ExportPath\UserCredentialReport.htm"

# Opens htm files
Invoke-Expression "$ExportPath\UserCredentialReport.htm"

# Leave Window Open
Read-Host -Prompt "Press Enter to exit"
