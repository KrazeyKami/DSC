<#
.SYNOPSIS
    Automates the download of the AzureFilesHyrbid Module for Domain Joining Storage Accuonts
    Automates the Domain Join tasks for the Storage Accounts
    Automates the deployment of relevant IAM roles
    Automates the configuration of NTFS permissions for FSLogix Containers
    Validates and outputs basic Storage Account Info
.DESCRIPTION
    Leverages the scripts provided by Microsoft
    https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable
.PARAMETER JoinStorageAccountToDomain
    If set, will join the storage account to the domain
.PARAMETER ConfigureIAMRoles
    Will configure Azure IAM roles
.PARAMETER ConfigureNTFSPermissions
    Will configure NTFS permissions for FSLogix Containers
.PARAMETER DebugStorageAccountDomainJoin
    Will debug join issues
.PARAMETER JSON
    Will consume a JSON import for configuration
.PARAMETER JSONInputPath
    Specifies the JSON input file 
.PARAMETER LogPath
    Logpath output for all operations
.PARAMETER LogRollover
    Number of days before logfiles are rolled over. Default is 5
.PARAMETER ValidateStorageAccount
    Will validate and output basic Storage Account Settings
.PARAMETER SetDefaultPermission
    Sets the default permission on the file share for authenticated users - no more requirement to specify a group https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-assign-permissions?tabs=azure-powershell#share-level-permissions-for-all-authenticated-identities
.PARAMETER EnableSMBMultiChannel
    Enables SMB MultiChannel on the storage account https://docs.microsoft.com/en-us/azure/storage/files/files-smb-protocol?tabs=azure-powershell#smb-multichannel
.PARAMETER UpdateAzStorageAccountAuthForAES256
    Configures AES256 encryption if required post configuration and join. https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-enable#enable-aes-256-encryption-recommended
.PARAMETER TenantID
    Sometimes if the account used to authenticate to Azure has access to multiple tenants, you may need to specify one due to MFA/Auth challenges. This parameter will enforce a "Connect-AzAccount -Tenant 'TenantID'" logic
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -JoinStorageAccountToDomain -ConfigureIAMRoles -ConfigureNTFSPermissions
    Will join the specified Storage account to the domain, configure IAM roles and configure NTFS permissions for Containers
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -ConfigureIAMRoles -ConfigureNTFSPermissions
    Will configure IAM roles and configure NTFS permissions for Containers
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -JoinStorageAccountToDomain -ConfigureIAMRoles -ConfigureNTFSPermissions -JSON -JSONInputPath C:\temp\azfiles.json
    Will import the specified JSON import file and join the specified Storage account to the domain, configure IAM roles and configure NTFS permissions for Containers
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -JoinStorageAccountToDomain -ConfigureIAMRoles -ConfigureNTFSPermissions -JSON -JSONInputPath C:\temp\azfiles.json -ValidateStorageAccount
    Will import the specified JSON import file and join the specified Storage account to the domain, configure IAM roles and configure NTFS permissions for Containers and output basic storage account details
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -JSON -JSONInputPath C:\temp\azfiles.json -ValidateStorageAccount
    Will output basic storage account details
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -JoinStorageAccountToDomain -ConfigureIAMRoles -ConfigureNTFSPermissions -JSON -JSONInputPath C:\temp\azfiles.json -ValidateStorageAccount -SetDefaultPermission -EnableSMBMultiChannel
    Will import the specified JSON import file and join the specified Storage account to the domain, configure IAM roles including the default and configure NTFS permissions for Containers and output basic storage account details. Will also enable SMB Multichannel
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -JoinStorageAccountToDomain -ConfigureIAMRoles -ConfigureNTFSPermissions -JSON -JSONInputPath C:\temp\azfiles.json -SetDefaultPermission -EnableSMBMultiChannel -TenantID 'WhateverYourAzureADTenantIDis'
    Will import the specified JSON import file and join the specified Storage account to the domain, configure IAM roles including the default and configure NTFS permissions for Containers. Will also enable SMB Multichannel. Will use a specific Tenant ID for Auth
.EXAMPLE
    JoinStorageAccountToDomain.ps1 -UpdateAzStorageAccountAuthForAES256 -JSON -JSONInputPath C:\temp\azfiles.json
    Will update an existing storage account with AES 256 Encryption
.NOTES
    Updates 17.06.2020
    - You can use a JSON import file (good) or alter variables within this script (not so good)
    - Added proper logging - no more write host
    - Optimised some basic code (Thanks Guy Leech)
    - Added some functions to clean up repetitive crud
    - Added a Validate Storage Acccount function to output basics around the target Storage Account including (Thanks Neil Spellings for the nudge)
        - Account Type (premium or Standard)
        - Expected IO and Burst IO
        - Firewall configuration
        - Private and Public Endpoint configurations
        - Large File Shares
    Updates 23.09.2020
    - Updated to version 0.2.2 (from 0.1.3) of the AZFilesHybrid Module https://github.com/Azure-Samples/azure-files-samples/releases/tag/v0.2.2
    - Updated ImportModule Function
    - Migrated ServiceLogonAccount logic to ComputerAccount due to incoming AES changes
    Updated 11.03.2021
    - Added Check for minimum PowerShellGet version
    - Added AzFilesHybrid Module 0.2.3
    - Added 15 Character limit check after being bitten too many times (thanks Dale!)
    Updated 01.02.2022
    - Updated to latest AZ Files Module 0.2.4 (https://github.com/Azure-Samples/azure-files-samples/releases/download/v0.2.4/AzFilesHybrid.zip)
    - Added Default Permission Switch, Defaults to StorageFileDataSmbShareContributor
    - Fixed JSON Template
    Updated 02.02.2022
    - Updated to use new commandlets
    - Fixed Module sections and removed functions (too lazy to fix)
    - Fixed extracted output path (due to change in AzFilesHybrid download)
    Updated 19.02.2022
    - Added SMB MultiChannel Switch
    - Removed Quota assessment given changes in Premium File Share IOPS
    - Added output for Storage File Services Properties
    Updated 13.08.22
    - Added AES 256 encryption as default
    - Added AES 256 encryption retrofit function and parameter (bring an existing storage account into AES 256 encryption and handle Active Directory)
    - Added TenantID Paramter to allow specifying a specific AzureAD tenant
#>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    # You may want to change this list below if you don't want to use parameters and simply accept defaults
    [Parameter(Mandatory = $false)]
    [Switch]$JoinStorageAccountToDomain,

    [Parameter(Mandatory = $false)]
    [Switch]$ConfigureIAMRoles,

    [Parameter(Mandatory = $false)]
    [Switch]$ConfigureNTFSPermissions,

    [Parameter(Mandatory = $false)]
    [Switch]$DebugStorageAccountDomainJoin,

    [Parameter(Mandatory = $false)]
    [Switch]$JSON,

    [Parameter(Mandatory = $false)]
    [String]$JSONInputPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Temp\StorageAccount.log", 

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # number of days before logfile rollover occurs

    [Parameter(Mandatory = $false)]
    [Switch]$ValidateStorageAccount,

    [Parameter(Mandatory = $false)]
    [Switch]$SetDefaultPermission,

    [Parameter(Mandatory = $false)]
    [Switch]$EnableSMBMultiChannel,

    [Parameter(Mandatory = $false)]
    [Switch]$UpdateAzStorageAccountAuthForAES256,

    [Parameter(Mandatory = $false)]
    [string]$TenantId
    
)
#endregion

#Change the execution policy to unblock importing AzFilesHybrid.psm1 module
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

Install-PackageProvider -Name Nuget -Force
Install-Module -Name "PowerShellGet" -AllowClobber -Force



#region variables
# ============================================================================
# Variables - change these per subscription (remove the "--") - If not using JSON input
# ============================================================================
$SubscriptionId = "--SubscriptionID--" #subscription Id
$TenantId = "--TenantId--" #Tenant Id
$ResourceGroupName = "--Resource Group--" #resource group name
$StorageAccountName = "--storage account name--" #storage account name
$ShareName = "--fslogix--" #storage account share name
$DomainAccountType = "ComputerAccount" #-DomainAccountType "<ComputerAccount|ServiceLogonAccount>"
$OU = "--OU=Azure FIles,DC=Domain,DC=com--" #-OrganizationalUnitDistinguishedName "<ou-distinguishedname-here>"
$EncryptionType = "AES256" #"<AES256|RC4|AES256,RC4>"
$SGAVDHostpoolDAG = @("WVD Users") # Array of groups to Assignment AVD Application Groups
$SGFSContributorGroups = @("WVD Users") # Array of groups to Assign Storage File Data SMB Share Contributor
$SGFSEleContributorGroups = @("WVD Users") # Array of groups to Assign Storage File Data SMB Share Contributor
$FSAdminUsers = @("Jkindon@domain.com") # Array of Admins to assign Storage File Data SMB Share Contributor and Storage File Data SMB Share Elevated Contributor roles
$DownloadUrl = "https://github.com/Azure-Samples/azure-files-samples/releases/download/v0.2.4/AzFilesHybrid.zip"
$ModulePath = "C:\temp\AzFilesHybrid" #Output path for modules
$DriveLetter = "X" # Letter used to map drive and set ACLs
$DCName = "--DCName--" # DCName

$User1 = $clearUserAzure0
$PWord1 = ConvertTo-SecureString -String $clearPassAzure0 -AsPlainText -Force
$Credential1 = New-Object System.Management.Automation.PSCredential($User1,$PWord1)
#endregion
		  
#region functions
# ============================================================================
# Functions
# ============================================================================

function JoinStorageAccountToDomain {
    # -OrganizationalUnitName "Azure Files"
    # If you don't provide the OU name as an input parameter, the AD identity that represents the storage account will be created under the root directory.
    Write-Log -Message "Attempting to Join Storage Account $StorageAccountName to Domain in OU $OU" -Level Info

    $JoinParams = @{
        ResourceGroupName                   = $ResourceGroupName
        Name                                = $StorageAccountName 
        DomainAccountType                   = $DomainAccountType
        OrganizationalUnitDistinguishedName = $OU
        EncryptionType                      = $EncryptionType
        ErrorAction                         = "Stop"
    }

    try {
        Join-AzStorageAccount @JoinParams -Confirm:$false
        Write-Log -Message "Successfully Joined Domain" -Level Info
    }
    catch {
        Write-Log -Message "Failed to Join Domain" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }

    if ($EncryptionType -eq "AES256") {
        Write-Log -Message "Encryption Type is AES256, updating Storage Account" -Level Info
        Update-AzStorageAccountAuthForAES256 -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Confirm:$false
    }    
}

function DebugStorageAccount {
    #You can run the Debug-AzStorageAccountAuth cmdlet to conduct a set of basic checks on your AD configuration with the logged on AD user. 
    #This cmdlet is supported on AzFilesHybrid v0.1.2+ version. For more details on the checks performed in this cmdlet, go to Azure Files FAQ.
    Debug-AzStorageAccountAuth -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName -Verbose    
}

function AssignIAMRoles {
    #Get the name of the custom role
	Write-Log -Message "Starting IAM Assignment..." -Level Info
    $FileShareReaderRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader" # not required for the most part, but added to admin account anyway to save on complexity
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor" # used for share access to the storage account - NTFS leveraged for fine grained controls
    $FileShareElevatedContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor" # used to set the admin accounts with permissions to manage NTFS

    #Constrain the scope to the target file share
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$ShareName"

    #Assign the custom role to the target identity with the specified scope.
    foreach ($Admin in $FSAdminUsers) {
        Write-Log -Message "Assigning Admin ID $Admin to Role $($FileShareReaderRole.Name)" -Level Info
        try {
            $ReaderRole = @{
                SignInName         = $Admin
                RoleDefinitionName = $FileShareReaderRole.Name
                Scope              = $scope
                ErrorAction        = "Ignore"
            }
            New-AzRoleAssignment @ReaderRole
            Write-Log -Message "Successfully added role assignment" -Level Info
        }
        catch {
            Write-Log -Message "Failed to assign role" -Level Warn
            Write-Log -Message $_ -Level Warn
        }

        Write-Log -Message "Assigning Admin ID $Admin to Role $($FileShareContributorRole.Name)" -Level Info
        try {
            $ContributorRole = @{
                SignInName         = $Admin
                RoleDefinitionName = $FileShareContributorRole.Name
                Scope              = $scope
                ErrorAction        = "Ignore"
            }
            New-AzRoleAssignment @ContributorRole
            Write-Log -Message "Successfully added role assignment" -Level Info
        }
        catch {
            Write-Log -Message "Failed to assign role" -Level Warn
            Write-Log -Message $_ -Level Warn
        }

        Write-Log -Message "Assigning Admin ID $Admin to Role $($FileShareElevatedContributorRole.Name)" -Level Info
        try {
            $ElevatedContributorRole = @{
                SignInName         = $Admin
                RoleDefinitionName = $FileShareElevatedContributorRole.Name
                Scope              = $scope
                ErrorAction        = "Ignore"
            }
            New-AzRoleAssignment @ElevatedContributorRole
            Write-Log -Message "Successfully added role assignment" -Level Info
        }
        catch {
            Write-Log -Message "Failed to assign role" -Level Warn
            Write-Log -Message $_ -Level Warn
        }
    }

    # Add Groups to Roles
    foreach ($Group in $SGFSContributorGroups) {
        Write-Log -Message "Assigning Group $Group to Role $($FileShareContributorRole.Name)" -Level Info
        try {
            $ContributorRoleGroup = @{
                ObjectId           = (Get-AzADGroup -SearchString $Group).Id
                RoleDefinitionName = $FileShareContributorRole.Name
                Scope              = $Scope
                ErrorAction        = "Ignore"
            }
            New-AzRoleAssignment @ContributorRoleGroup
            Write-Log -Message "Successfully added role assignment" -Level Info
        }
        catch {
            Write-Log -Message "Failed to assign role" -Level Warn
            Write-Log -Message $_ -Level Warn
        }
    }

    # Add Groups to Roles
    foreach ($Group in $SGFSEleContributorGroups) {
        Write-Log -Message "Assigning Group $Group to Role $($FileShareElevatedContributorRole.Name)" -Level Info
        try {
            $ContributorRoleGroup = @{
                ObjectId           = (Get-AzADGroup -SearchString $Group).Id
                RoleDefinitionName = $FileShareElevatedContributorRole.Name
                Scope              = $Scope
                ErrorAction        = "Ignore"
            }
            New-AzRoleAssignment @ContributorRoleGroup
            Write-Log -Message "Successfully added role assignment" -Level Info
        }
        catch {
            Write-Log -Message "Failed to assign role" -Level Warn
            Write-Log -Message $_ -Level Warn
        }
    }
	
	 # Add Groups to Roles
    foreach ($Group in $SGAVDHostpoolDAG) {
        Write-Log -Message "Assigning Group $Group to AVD application group assignment" -Level Info
        try {
            # Get the object ID of the user group you want to assign to the application group
			$userGroupId = (Get-AzADGroup -DisplayName "$SGAVDHostpoolDAG").Id

			# Assign users to the application group
			$parameters = @{
				ObjectId = $userGroupId
				ResourceName = "$HostPoolName0-DAG"
				ResourceGroupName = "$workspaceResourceGroup0"
				RoleDefinitionName = 'Desktop Virtualization User'
				ResourceType = 'Microsoft.DesktopVirtualization/applicationGroups'
				ErrorAction        = "Ignore"
			}

			New-AzRoleAssignment @parameters
            Write-Log -Message "Successfully added application group assignment" -Level Info
        }
        catch {
            Write-Log -Message "Failed to assign role" -Level Warn
            Write-Log -Message $_ -Level Warn
        }
    }
	
	#Update AVD Desktop Friendly name
	Update-AzWvdDesktop -ResourceGroupName $workspaceResourceGroup0 -ApplicationGroupName $HostPoolName0-DAG -Name SessionDesktop -FriendlyName "Virtual Desktop"
	
	
	
	


}

function ConfigureNTFSPermissions {
    $StorageAcccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName
    $Key = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName $StorageAcccount.StorageAccountName | Where-Object { $_.KeyName -eq "Key1" }
    $Path = "\\" + $StorageAccountName + ".file.core.windows.net" + "\" + $ShareName
    $DriveLetter = ($DriveLetter + ":")
    
    $connectTestResult = Test-NetConnection -ComputerName ($StorageAccountName + ".file.core.windows.net") -Port 445
    if ($connectTestResult.TcpTestSucceeded) {
        try {
            $DriveParams = @{
                LocalPath   = $DriveLetter
                RemotePath  = $Path
                UserName    = ("Azure\" + $StorageAccountName)
                Password    = $Key.Value
                ErrorAction = "Stop"
            }
            $null = New-SmbMapping @DriveParams
        }
        catch {
            Write-Log -Message "Drive Failed to map. Exiting" -Level Warn
            Write-Log -Message $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    else {
        Write-Log -Message "Unable to reach the Azure storage account via port 445" -Level Warn
        StopIteration
        Exit 1
    }
    
    Write-Log -Message "Existing NTFS permissions are:" -Level Info
    icacls $DriveLetter
    
    Write-Log -Message "Setting new NTFS permissions:" -Level Info
    icacls $DriveLetter /remove "Authenticated Users"
    icacls $DriveLetter /grant '"Authenticated Users":(M)'
    icacls $DriveLetter /grant '"Creator Owner":(OI)(CI)(IO)(M)'
    icacls $DriveLetter /remove "Builtin\Users"
    
    Write-Log -Message "New permissions are:" -Level Info
    icacls $DriveLetter
    
    Write-Log -Message "Removing mapped drive" -Level Info
    Remove-SmbMapping -LocalPath $DriveLetter -Force
}

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = $LogPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$NoClobber
    )

    Begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
        }

        else {
            # Nothing to see here yet.
        }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
            }
        }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}

function Start-Stopwatch {
    Write-Log -Message "Starting Timer" -Level Info

    $Global:StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    
}

function Stop-Stopwatch {
    Write-Log -Message "Stopping Timer" -Level Info
    $StopWatch.Stop()
    if ($StopWatch.Elapsed.TotalSeconds -le 1) {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalMilliseconds) ms to complete." -Level Info
    }
    else {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalSeconds) seconds to complete." -Level Info
    }
}

function RollOverlog {
    $LogFile = $LogPath
    $LogOld = Test-Path $LogFile -OlderThan (Get-Date).AddDays(-$LogRollover)
    $RolloverDate = (Get-Date -Format "dd-MM-yyyy")
    if ($LogOld) {
        Write-Log -Message "$LogFile is older than $LogRollover days, rolling over" -Level Info
        $NewName = [io.path]::GetFileNameWithoutExtension($LogFile)
        $NewName = $NewName + "_$RolloverDate.log"
        Rename-Item -Path $LogFile -NewName $NewName
        Write-Log -Message "Old logfile name is now $NewName" -Level Info
    }    
}

function StartIteration {
    Write-Log -Message "--------Starting Iteration--------" -Level Info
	
    RollOverlog
    Start-Stopwatch
}

function StopIteration {
    Stop-Stopwatch	
	
    Write-Log -Message "--------Finished Iteration--------" -Level Info
    Push-Location -Path $PSScriptRoot
}

function ValidateStorageAccount {
    $StorageAcccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName

    if ($StorageAcccount.Sku.Tier -eq "Premium") {
        Write-Log -Message "Storage Account $($StorageAccountName) is a $($StorageAcccount.Sku.Tier) Account" -Level Info

        try {
            $Share = Get-AzStorageShare -Name $ShareName -context $StorageAcccount.Context -ErrorAction Stop
        }
        catch {
            Write-Log -Message "Share not found" -Level Warn
            Write-Log -Message "$_" -Level Warn
            StopIteration
            exit 1
        }

        Write-Log -Message "The share $($ShareName) has a quota (size) of $($Share.Quota) GiB" -Level Info
    }
    else {
        Write-Log -Message "Storage Account $($StorageAccountName) is a $($StorageAcccount.Sku.Tier) Account" -Level Info
        Write-Log -Message "Premium File Shares are recommended for FSLogix Container workloads" -Level Warn
    }

    $DefaultAction = $StorageAcccount.NetworkRuleSet.DefaultAction #Firewall Action
    $ServiceBypass = $StorageAcccount.NetworkRuleSet.Bypass #(Trusted Services)
    $AllowedNetworks = $StorageAcccount.NetworkRuleSet.VirtualNetworkRules.VirtualNetworkResourceId #allowed vnets
    $AllowedIPs = $StorageAcccount.NetworkRuleSet.IpRules #inbound rules
    $LargeFileShares = $StorageAcccount.LargeFileSharesState #Large file shares are enabled
    $DefaultPermissionSet = $StorageAcccount.AzureFilesIdentityBasedAuth #Default permission configuration

    #Default Security Stance
    if ($DefaultAction -eq "Deny") {
        Write-Log -Message "The default firewall action is set to Deny on the Storage Account: $($StorageAccountName)" -Level Info
    }
    else {
        Write-Log -Message "The default firewall action is set to allow on the Storage Account: $($StorageAccountName)" -Level Info
    }

    # Service Bypass
    if ($ServiceBypass -eq "AzureServices") {
        Write-Log -Message "Azure services are allowed to bypass the Storage Account Firewall for Storage Account: $($StorageAccountName)" -Level Info
    }
    else {
        Write-Log -Message "Azure Services cannot bypass the Storage Account Firewall for Storage Account: $($StorageAccountName)" -Level Info
    }

    #Large File Shares
    if ($LargeFileShares -eq "Enabled") {
        Write-Log -Message "Large File Shares are enabled on the Storage Account: $($StorageAccountName)" -Level Info
        if ($StorageAcccount.Sku.Tier -eq "Standard") {
            Write-Log -Message "A Standard Storage Account with Large File Shares enabled has a maximum IO capability of 10,000 IOPS" -Level Info
        }
    }
    else {
        Write-Log -Message "Large File shares are not enabled on the Storage Account: $($StorageAccountName)" -Level Info
        Write-Log -Message "A Standard Storage Account without Large File Shares enabled has a maximum IO capability of 1,000 IOPS" -Level Info
    }

    # Default Permissions
    if ($null -eq $DefaultPermissionSet) {
        Write-Log -Message "Default file share permissions are not enabled on the Storage Account: $($StorageAccountName)" -Level Info
    }
    else {
        Write-Log -Message "Default file share permissions are set to: DefaultPermissionSet on Storage Account: $($StorageAccountName)" -Level Info
    }

    # Network Configurations - Firewall
    if ($null -eq $AllowedNetworks) {
        Write-Log -Message "There are no defined VNET objects on the Storage Account Firewall for Storage Account: $($StorageAccountName)" -Level Info
    }
    else {
        Write-Log -Message "The following VNET and Subnets have been defined on the Storage Account Firewall for Storage Account: $($StorageAccountName)" -Level Info
        foreach ($_ in $AllowedNetworks) {
            Write-Log -Message "Subnet: $(($_ | Split-Path -Leaf)) in VNET: $($_.Split("/") | Select-Object -Index 8)" -Level Info
        }
    }

    #Allowed IP configurations - Firewall 
    if ($AllowedIPs.Count -eq 0) {
        Write-Log -Message "There are no defined IP objects on the Storage Account Firewall for Storage Account: $($StorageAccountName)" -Level Info
    }
    else {
        Write-Log -Message "$($AllowedIPs.Count) IP objects have been defined on the Storage Account Firewall for Storage Account: $($StorageAccountName)" -Level Info
        foreach ($IP in $AllowedIPs) {
            Write-Log -Message "$($IP.IPAddressOrRange) has been defined with the following action type: $($IP.Action)" -Level Info
        }
    }

    $null = Get-AzPrivateEndpoint | Where-Object { $_.PrivateLinkServiceConnections.Id -like "*$StorageAccountName*" }
    $PrivateEndpoint = Get-AzPrivateEndpoint | Where-Object { $_.PrivateLinkServiceConnections.Id -like "*$StorageAccountName*" }
    $ApprovedPrivateEndpoint = $PrivateEndpoint.PrivateLinkServiceConnections.PrivateLinkServiceConnectionState.Status
    if ($ApprovedPrivateEndpoint -eq "Approved") {
        $Subnet = $PrivateEndpoint.Subnet.Id | Split-Path -Leaf
        Write-Log -Message "There is an approved Private Endpoint attached to the Storage Account: $($PrivateEndpoint.Name) attached to subnet: $Subnet" -Level Info
    }
    else {
        Write-Log -Message "There are no private endpoints configured on the Storage Account: $($StorageAccountName)" -Level Info
    }
}

function ValidateStorageAccountNameCharacterCount {
    if ($StorageAccountName.length -gt 15 ) {
        Write-Log -Message "The Storageaccount name exceeds 15 characters ($($StorageAccountName.length)) and cannot be joined to the Domain. Script is exiting" -Level Warn
        StopIteration
        Exit 1
    }
    else {
        Write-Log -message "Storageaccount name is less than 15 characters. Continuing" -Level Info
    }
}

function SetDefaultPermission {
    $defaultPermission = "StorageFileDataSmbShareContributor" # Set the default permission of your choice ("None|StorageFileDataSmbShareContributor|StorageFileDataSmbShareReader|StorageFileDataSmbShareElevatedContributor")
    Write-Log -Message "Setting default permission to: $($defaultPermission) " -Level Info
    $account = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName -DefaultSharePermission $defaultPermission | Out-null
    #$account.AzureFilesIdentityBasedAuth
}

function EnableSMBMultiChannel {
     Write-Log -Message "Enabling SMB MultiChannel" -Level Info
     if (((Get-AzStorageFileServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName).ProtocolSettings.Smb.Multichannel.Enabled) -ne "True") {
         try {
            Write-Log -Message "SMB MultiChannel is not enabled. Enabling" -Level Info
            Update-AzStorageFileServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -EnableSmbMultichannel $True -Confirm:$false -ErrorAction Stop
            Write-Log -Message "SMB MultiChannel enabled" -Level Info
         }
         catch {
            Write-Log -Message "SMB MultiChannel enablement failed. Exiting" -Level Warn
            Write-Log -Message $_ -Level Warn
         }
     }
     else {
        Write-Log -Message "SMB MultiChannel is already enabled" -Level Info
     }
}

function UpdateAzStorageAccountAuthForAES256 {
    Write-Log -Message "Updating Storage Account for AES 256 Kerberos Encryption" -Level Info
    try {
        Update-AzStorageAccountAuthForAES256 -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Confirm:$false
        Write-Log -Message "Setting Computer Account Encryption to AES 256" -Level Info
        Get-ADComputer -Identity $StorageAccountName | Set-ADComputer -KerberosEncryptionType "AES256" -Confirm:$false
        Write-Log -Message "Setting Storage Account keys" -Level Info
        $KeyName = "kerb1" # Could be either the first or second kerberos key, this script assumes we're refreshing the first
        $KerbKeys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName $KeyName -Confirm:$false
        $KerbKey = $KerbKeys.keys | Where-Object {$_.KeyName -eq $KeyName} | Select-Object -ExpandProperty Value
        $NewPassword = ConvertTo-SecureString -String $KerbKey -AsPlainText -Force
        Write-Log -Message "Setting AD Account Password" -Level Info
        Get-ADComputer -Identity $StorageAccountName | Set-ADAccountPassword -Identity $StorageAccountName -Reset -NewPassword $NewPassword -Confirm:$false
    }
    catch {
        Write-Log -Message "Failed to set Storage Account for AES 256 Kerberos Encryption" -Level Warn
        Write-Log -Message $_ -Level Warn
    }
}

#endregion

#region execute


# ============================================================================
# Handle JSON input
# ============================================================================
if ($JSON.IsPresent) {
    Write-Log -Message "JSON input selected. Importing JSON data from: $JSONInputPath" -Level Info
    try {
        if (!(Test-Path $JSONInputPath)) {
            Write-Log -Message "Cannot find file: $JSONInputPath" -Level Warn
            StopIteration
            Exit 1
        }
        $EnvironmentDetails = Get-Content -Raw -Path $JSONInputPath -ErrorAction Stop | ConvertFrom-Json
    }
    catch {
        Write-Log -Message "JSON import failed. Exiting" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }

    $SubscriptionId = $EnvironmentDetails.SubscriptionId #subscription Id
    $TenantId = $EnvironmentDetails.TenantId #tenant Id
    $ResourceGroupName = $EnvironmentDetails.ResourceGroupName #resource group name
    $StorageAccountName = $EnvironmentDetails.StorageAccountName #storage account name
    $ShareName = $EnvironmentDetails.ShareName #storage account share name
    $DomainAccountType = $EnvironmentDetails.DomainAccountType #-DomainAccountType "<ComputerAccount|ServiceLogonAccount>"
    $OU = $EnvironmentDetails.OU #-OrganizationalUnitDistinguishedName "<ou-distinguishedname-here>"
    $EncryptionType = $EnvironmentDetails.EncryptionType	
	$SGAVDHostpoolDAG = $EnvironmentDetails.SGAVDHostpoolDAG -replace "@{name=", "" -replace "}", "" # Array of groups to Assign Storage File Data SMB Share Contributor
    $SGFSContributorGroups = $EnvironmentDetails.SGFSContributorGroups -replace "@{name=", "" -replace "}", "" # Array of groups to Assign Storage File Data SMB Share Contributor
    $SGFSEleContributorGroups = $EnvironmentDetails.SGFSEleContributorGroups -replace "@{name=", "" -replace "}", "" # Array of groups to Assign Storage File Data SMB Share Elevated Contributor
    $FSAdminUsers = $EnvironmentDetails.FSAdminUsers -replace "@{name=", "" -replace "}", "" # Array of Admins to assign Storage File Data SMB Share Contributor and Storage File Data SMB Share Elevated Contributor roles
    $DownloadUrl = $EnvironmentDetails.DownloadUrl
    $ModulePath = $EnvironmentDetails.ModulePath -replace "//", "\" #Output path for modules
    $DriveLetter = $EnvironmentDetails.DriveLetter # Letter used to map drive and set ACLs
	#$clearUserAzure = $EnvironmentDetails.clearUserAzure # HybridCreds1
    #$clearPassAzure = $EnvironmentDetails.clearPassAzure # HybridCreds2
}

Write-Log -Message "Subscription ID is set to: $($SubscriptionId)" -Level Info
Write-Log -Message "Resource Group name is set to: $($ResourceGroupName)" -Level Info
Write-Log -Message "Storage account name is set to: $($StorageAccountName)" -Level Info
Write-Log -Message "Share Name is set to: $($ShareName)" -Level Info
Write-Log -Message "Domain account type is set to: $($DomainAccountType)" -Level Info
Write-Log -Message "OU is set to: $($OU)" -Level Info
Write-Log -Message "AVD User groups defined: $($SGAVDHostpoolDAG)" -Level Info
Write-Log -Message "File Server Contributor groups defined: $($SGFSContributorGroups)" -Level Info
Write-Log -Message "File Server Elevated Contributor groups defined: $($SGFSEleContributorGroups)" -Level Info
Write-Log -Message "File Server Admin users defined: $($FSAdminUsers)" -Level Info
Write-Log -Message "Download URL is set to: $($DownloadUrl)" -Level Info
Write-Log -Message "Module path is set to: $($ModulePath)" -Level Info
Write-Log -Message "Driver letter is set to: $($DriveLetter)" -Level Info
 

 
#Checking if Storage Account was already joined. 
 try{
	 
	 $StoragePresent = Get-ADComputer $StorageAccountName
	 
        if ($StoragePresent -ne $null)
			{
				Write-Log -Message "Storage Account $StorageAccountName is already joined. Assigning IAM Roles...)" -Level Info
				AssignIAMRoles				
				Exit	
			}
        else
			{
				Write-Log -Message "Storage Account $StorageAccountName NOT joined... Starting Iteration.)" -Level Info
				StartIteration
			}
		}catch{
			 	Write-Log -Message "Storage Account $StorageAccountName NOT joined... Starting Iteration.)" -Level Info
                StartIteration
	}	


# ============================================================================
# Validate Storage Account Name Count (looking for 15 characters or less)
# ============================================================================
ValidateStorageAccountNameCharacterCount

# ============================================================================
# Download and Import Module
# ============================================================================
$OutFile = $ModulePath + "\" + ($DownloadUrl | Split-Path -Leaf)

$AZFilesHybrid = (Get-Module -Name "AZFilesHybrid")
if ($null -ne $AZFilesHybrid) {
    Write-Log -Message "AZFilesHybrid version $($AZFilesHybrid.Version) is installed" -Level Info
    #Import AzFilesHybrid module    
    Import-Module -Name "AZFilesHybrid" -Force
}
else {
    if (!(Test-Path -Path $ModulePath)) {
        $null = New-Item -Path $ModulePath -ItemType Directory
    }
    try {
        Write-Log -Message "Downloading AZFilesHybrid PowerShell Module" -Level Info
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $OutFile -ErrorAction Stop
        Expand-Archive -Path $OutFile -DestinationPath $ModulePath -Force
        # Navigate to where AzFilesHybrid is unzipped and stored and run to copy the files into your path
        Push-Location $ModulePath #\AZFilesHybrid
        .\CopyToPSPath.ps1
        #Import AzFilesHybrid module
        Import-Module -Name "AZFilesHybrid" -Force -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Failed to Download AzFilesHybrid Module. Exiting" -Level Warn
        StopIteration
        Exit 1
    }    
}


$AZStorage = (Get-Module -Name "AZ.Storage")
if ($null -ne $AZStorage) {
    Write-Log -Message "AZ.Storage version $($AZStorage.Version) is installed" -Level Info
    Import-Module -Name "AZ.Storage" -Force
}
else {
    try {
        Write-Log -Message "AZ.Storage is not installed. Attempting Install" -Level Info
        Install-Module -Name "AZ.Storage"-AllowClobber -ErrorAction Stop -Force
        Import-Module -Name "AZ.Storage" -Force
    }
    catch {
        Write-Log -Message "Failed to Import Module AZ.Storage. Exiting" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }    
}

Import-Module -Name "PowerShellGet" -Force
$PowerShellGet = (Get-Module -Name "PowerShellGet")
if ($null -ne $PowerShellGet) {
    Write-Log -Message "PowerShellGet version $($PowerShellGet.Version) is installed" -Level Info
    if ($PowerShellGet.Version -gt "1.6.0") {
    Write-Log -Message "Importing Module: PowerShellGet" -Level Info
            Import-Module -Name "PowerShellGet" -Force
        }
    else {
        Write-Log "$($PowerShellGet.Version) installed. Forcing an update"
        try {
            Remove-Module PackageManagement -Force					
            Install-Module -Name "PowerShellGet" -AllowClobber -SkipPublisherCheck -ErrorAction Stop -Force
            Import-Module -Name "PowerShellGet" -Force
        }
        catch {
            Write-Log -Message $_ -Level Warn
            StopIteration
            Exit 1    
        }
    }
}
else {
    try {
        Write-Log -Message "PowerShellGet is not installed. Attempting Install" -Level Info		
        Install-Module -Name "PowerShellGet" -AllowClobber -ErrorAction Stop -Force
        Import-Module -Name "PowerShellGet" -Force -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Failed to Import Module PowerShellGet. Exiting" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }    
}

# ============================================================================
# Select Azure Subscription
# ============================================================================
#Login with an Azure AD credential that has either storage account owner or contributer RBAC assignment
Write-Log -Message "Connecting to Azure" -Level Info


 
try {
    if ($TenantId -eq $null) {
        Write-Log -Message "Not using a specific Tenant ID" -Level Info
        $null = Connect-AzAccount -Credential $Credential1 -ErrorAction Stop
    }
    else {
        Write-Log -Message "Specified a Tenant ID of $($TenantId)" -Level Info
        $null = Connect-AzAccount -Credential $Credential1 -Tenant $TenantId -ErrorAction Stop
    }
    Write-Log -Message "Connected to Azure" -Level Info
    Write-Log -Message "Setting Subscription $($SubscriptionId)" -Level Info
    $null = Select-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
}
catch {
    Write-Log -Message "Failed to set Azure Subscription. Exiting" -Level Warn
    StopIteration
    Exit 1    
}

# ============================================================================
# Join Storage Account
# ============================================================================
if ($JoinStorageAccountToDomain.IsPresent) {
    JoinStorageAccountToDomain
}

# ============================================================================
# Debug if required
# ============================================================================
if ($DebugStorageAccountDomainJoin.IsPresent) {
    DebugStorageAccount
}

# ============================================================================
# Assign Roles
# ============================================================================
if ($ConfigureIAMRoles.IsPresent) {
    AssignIAMRoles
}

# ============================================================================
# Set NTFS permissions for Containers
# ============================================================================
if ($ConfigureNTFSPermissions.IsPresent) {
    ConfigureNTFSPermissions
}

# ============================================================================
# Set Default Permission for Share Access
# ============================================================================
if ($SetDefaultPermission.IsPresent) {
    SetDefaultPermission
}

# ============================================================================
# Enable SMTP MultiChannel
# ============================================================================
if ($EnableSMBMultiChannel.IsPresent) {
    EnableSMBMultiChannel
}

# ============================================================================
# Validate Storage Account
# ============================================================================
if ($ValidateStorageAccount.IsPresent) {
    ValidateStorageAccount
}

# ============================================================================
# Enable Storage Account Auth for AES 256 Encryption
# ============================================================================
if ($UpdateAzStorageAccountAuthForAES256.IsPresent) {
    UpdateAzStorageAccountAuthForAES256
}

# ============================================================================
# Output File Service security basics for the storage account
# ============================================================================
Write-Log -Message "Storage Account properties are outlined below. Please review and update as per requirements" -Level Info
try {
    Get-AzStorageFileServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
}
catch {
    Write-Log -Message "Failed to get storage account file services properties" -Level Warn
    Write-Log -Message $_ -Level Warn
}

StopIteration
Exit 0
#endregion



