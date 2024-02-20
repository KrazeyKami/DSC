get-childitem cert:\localmachine\my | where-object {$_.Subject -like "*CN=DscEncryptionCert*"} | remove-item

$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'DscEncryptionCert' -HashAlgorithm SHA256
$cert | Export-Certificate -FilePath "C:\TEMP\DscPublicKey.cer" -Force

$Thumbprint = (get-childitem cert:\localmachine\my | where-object {$_.Subject -like "*CN=DscEncryptionCert*"}).Thumbprint

	if (Test-Path C:\temp\AVDDSC\AVDGPOs) 
			 	  	{			 	  		
			 	  	} 
			 	  	else
			 	  	{
			 	  		New-Item "C:\temp\AVDDSC\AVDGPOs" -Type Directory
			 	  	}


$ConfigData= @{ 
    AllNodes = @(     
            @{   
                NodeName = "localhost" 

                CertificateFile = "C:\TEMP\DscPublicKey.cer" 

                Thumbprint = $Thumbprint 
            }; 
        );    
    }


Configuration CreateNewADForest {
param
    #v1.4
   ( 
		[Parameter(Mandatory)]
        [String]$AADTenantName,
		
		[Parameter(Mandatory)]
        [String]$DLLAADC,
		
		[Parameter(Mandatory)]
        [String]$AtSign,		
		
		[Parameter(Mandatory)]
        [String]$RemoteDSCRepo,	
		
		[Parameter(Mandatory)]
        [String]$dlNewtonsoft,
		
		[Parameter(Mandatory)]
        [String]$dlADMX,
		
		[Parameter(Mandatory)]
        [String]$AVD0hostIP,		
		
		[Parameter(Mandatory)]
        [String]$dlFSLOGIX,
		
		[Parameter(Mandatory)]
        [String]$dlAADC,
		
		[Parameter(Mandatory)]
        [String]$dlSAjoin,
		
		[Parameter(Mandatory)]
        [String]$dlAVDGPOs,
		
        [Parameter(Mandatory)]
        [String]$DomainName,	
		
		[Parameter(Mandatory)]
        [String]$CustomDomainName,

		[Parameter(Mandatory)]
        [String]$DomainDN,
		
		[Parameter(Mandatory)]
        [String]$AvdAdminUserName,	

		[Parameter(Mandatory)]
        [String]$FirstUserName,	
		
		[Parameter(Mandatory)]
        [String]$DCName,	
		
		[Parameter(Mandatory)]
        [String]$SubscriptionId,
		
		[Parameter(Mandatory)]
        [String]$TenantId,
		
		[Parameter(Mandatory)]
        [String]$ResourceGroupName,
		
		[Parameter(Mandatory)]
        [String]$StorageAccountName,
		
		[Parameter(Mandatory)]
        [String]$ShareName,
		
		[Parameter(Mandatory)]
        [String]$SGAVDLocalAdmins,		
		
		[Parameter(Mandatory)]
        [String]$SGAVDHostpoolDAG,		
		
		[Parameter(Mandatory)]
        [String]$DomainAccountType,
		
		[Parameter(Mandatory)]
        [String]$OU,
		
		[Parameter(Mandatory)]
        [String]$EncryptionType,
		
		[Parameter(Mandatory)]
        [String]$SGFSContributorGroups,
		
		[Parameter(Mandatory)]
        [String]$SGFSEleContributorGroups,
		
		[Parameter(Mandatory)]
        [String]$FSAdminUsers,
		
		[Parameter(Mandatory)]
        [String]$DownloadUrl,
		
		[Parameter(Mandatory)]
        [String]$ModulePath,
		
		[Parameter(Mandatory)]
        [String]$DriveLetter,		
		
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,
		
		[Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$hybridAdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SafeModeAdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$myFirstUserCreds,
		
		[Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AVDAdminUserCreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )
	
	Install-PackageProvider -Name Nuget -Force
	Install-module PSAdvancedJsonCmdlet -Force
	Import-module PSAdvancedJsonCmdlet -Force
	
    Import-DscResource -ModuleName xActiveDirectory, xNetworking, xPendingReboot, DnsServerDsc, ActiveDirectoryDsc, xPSDesiredStateConfiguration, xDscDiagnostics, xDscResourceDesigner, DSCR_FileContent
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

	
	$clearUserAdmin = $AdminCreds.GetNetworkCredential().username
	$clearPassAdmin = $AdminCreds.GetNetworkCredential().password | Protect-CmsMessage -To $Thumbprint

	$clearUserAzure = $hybridAdminCreds.GetNetworkCredential().username
	$clearPassAzure = $hybridAdminCreds.GetNetworkCredential().password | Protect-CmsMessage -To $Thumbprint
	
	$clearUserAVD = $AVDAdminUserCreds.GetNetworkCredential().username
	$clearPassAVD = $AVDAdminUserCreds.GetNetworkCredential().password | Protect-CmsMessage -To $Thumbprint

	$clearUserTest = $myFirstUserCreds.GetNetworkCredential().username
	$clearPassTest = $myFirstUserCreds.GetNetworkCredential().password | Protect-CmsMessage -To $Thumbprint
	
	   
	
    Node localhost
    {
	
		#Format Drive:
		if (Test-Path "F:\") {}
		else {
   			Initialize-Disk -Number 2 -PartitionStyle GPT
			New-Partition -DiskNumber 2 -DriveLetter F -UseMaximumSize
			Format-Volume -DriveLetter F -FileSystem NTFS -NewFileSystemLabel NTDS
		}		
        LocalConfigurationManager            
        {            
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true 
			CertificateId = $Thumbprint 			
        } 

        WindowsFeature DNS 
        { 
            Ensure = "Present" 
            Name = "DNS"
        }
		
        #WindowsFeature RSAT
        #{
        #    Ensure = "Present"
        #    Name = "RSAT"
        #}
		
		WindowsFeature RSAT-ADDS
		{
			Ensure = "Present"
            Name = "RSAT-ADDS"			
		}
		
		WindowsFeature RSAT-ADDS-Tools
		{
			Ensure = "Present"
            Name = "RSAT-ADDS-Tools"			
		}		

        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services"	
						
        }  
		
		WindowsFeature RSAT-DNS-Server 
        { 
            Ensure = "Present" 
            Name = "RSAT-DNS-Server"
        } 

		WindowsFeature Telnet-Client
        { 
            Ensure = "Present" 
            Name = "Telnet-Client"
        }  	

		WindowsFeature RSAT-DFS-Mgmt-Cont
        { 
            Ensure = "Present" 
            Name = "RSAT-DFS-Mgmt-Con"
        }  	
		
			DnsServerForwarder 'SetForwarders'
        {
            IsSingleInstance = 'Yes'
            IPAddresses = @('168.63.129.16')
            UseRootHint = $false
			DependsOn = "[xWaitForADDomain]DscForestWait"
        }
		
		 DnsServerConditionalForwarder 'Forwarder1'
        {
            Name = 'core.windows.net'
            MasterServers = @('168.63.129.16')
            ReplicationScope = 'Forest'
            Ensure = 'Present'
			DependsOn = "[xWaitForADDomain]DscForestWait"
        }
		
		DnsServerADZone 'addReverseADZone1'
        {
            Name = '100.0.10.in-addr.arpa'
            DynamicUpdate = 'Secure'
            ReplicationScope = 'Forest'
            Ensure = 'Present'
			DependsOn = "[xWaitForADDomain]DscForestWait"
        }
		
			DnsServerADZone 'addReverseADZone2'
        {
            Name = '101.0.10.in-addr.arpa'
            DynamicUpdate = 'Secure'
            ReplicationScope = 'Forest'
            Ensure = 'Present'
			DependsOn = "[xWaitForADDomain]DscForestWait"
        }
		
			DnsServerADZone 'addReverseADZone3'
        {
            Name = '102.0.10.in-addr.arpa'
            DynamicUpdate = 'Secure'
            ReplicationScope = 'Forest'
            Ensure = 'Present'
			DependsOn = "[xWaitForADDomain]DscForestWait"
        }
		
		ADReplicationSite 'Azure-Site'
		{
			Name  = 'Azure-Site'
			Ensure  = 'Present'
			DependsOn = "[xWaitForADDomain]DscForestWait"
		}

		ADReplicationSubnet 'Azure-Subnet'
		{
			Name  = '10.0.0.0/16'
			Site  = 'Azure-Site'
			DependsOn = '[ADReplicationSite]Azure-Site'
			Ensure  = 'Present'						
		}


        xADDomain FirstDC 
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $SafeModeAdminCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $DomainName
            DomainUserCredential = $DomainCreds
            RetryCount = $RetryCount
            RetryIntervalSec = $RetryIntervalSec
            DependsOn = "[xADDomain]FirstDC"
        }

		ADForestProperties Configuration
		{
			ForestName = $DomainName
			UserPrincipalNameSuffixToAdd = $CustomDomainName
			DependsOn = "[xWaitForADDomain]DscForestWait"
		}
		
		#Create OUs:
	
		ADOrganizationalUnit 'Resources'
        {
            Name                            = "RESOURCES"
            Path                            = "$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Resource OU"
            Ensure                          = 'Present'
			
        }
		ADOrganizationalUnit 'Servers'
        {
            Name                            = "SERVERS"
            Path                            = "OU=RESOURCES,$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Server OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Resources"
		}
		ADOrganizationalUnit 'MGMT'
        {
            Name                            = "MGMT"
            Path                            = "OU=SERVERS,OU=RESOURCES,$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Management Server OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Servers"
		}
		ADOrganizationalUnit 'AVD'
        {
            Name                            = "AVD"
            Path                            = "OU=SERVERS,OU=RESOURCES,$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Azure Virtual Desktop OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Servers"
		}
		ADOrganizationalUnit 'Workstations'
        {
            Name                            = "WORKSTATIONS"
            Path                            = "OU=RESOURCES,$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Workstation OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Resources"
		}
		ADOrganizationalUnit 'Groups'
        {
            Name                            = "GROUPS"
            Path                            = "OU=RESOURCES,$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Groups OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Resources"
		}
		ADOrganizationalUnit 'AZURE-SYNC-g'
        {
            Name                            = "AZURE-SYNC"
            Path                            = "OU=GROUPS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Groups that sync to Azure OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Groups"
		}
		ADOrganizationalUnit 'NO-SYNC-g'
        {
            Name                            = "NO-SYNC"
            Path                            = "OU=GROUPS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Groups that don't sync to Azure OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Groups"
		}
		ADOrganizationalUnit 'Accounts'
        {
            Name                            = "ACCOUNTS"
            Path                            = "OU=RESOURCES,$domainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Accounts OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Resources"
		}
		ADOrganizationalUnit 'ADMINS'
        {
            Name                            = "ADMINS"
            Path                            = "OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Admin Accounts OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Accounts"
		}
		ADOrganizationalUnit 'SERVICEACCOUNTS'
        {
            Name                            = "SERVICEACCOUNTS"
            Path                            = "OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Service Accounts OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Accounts"
		}
		ADOrganizationalUnit 'STORAGEACCOUNTS'
        {
            Name                            = "STORAGEACCOUNTS"
            Path                            = "OU=SERVICEACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "Storage Accounts OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]SERVICEACCOUNTS"
		}
		ADOrganizationalUnit 'USERACCOUNTS'
        {
            Name                            = "USERACCOUNTS"
            Path                            = "OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "User Accounts OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]Accounts"
		}
		ADOrganizationalUnit 'AZURE-SYNC-U'
        {
            Name                            = "AZURE-SYNC"
            Path                            = "OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "User Accounts that sync to Azure OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]USERACCOUNTS"
		}
		ADOrganizationalUnit 'AZURE-NOSYNC-U'
        {
            Name                            = "NO-SYNC"
            Path                            = "OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
            ProtectedFromAccidentalDeletion = $true
            Description                     = "User Accounts that don't sync to Azure  OU"
			Ensure                          = 'Present'
			DependsOn 						= "[ADOrganizationalUnit]USERACCOUNTS"
		}

		
		xADUser AVDAdmin
		{ 
		DomainName = $DomainName 		
		DomainAdministratorCredential = $DomainCreds 
		UserName = $AVDAdminUserCreds.UserName 
		Password = $AVDAdminUserCreds
		Ensure = "Present"
		Path = "OU=AZURE-SYNC,OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
		UserPrincipalName = "$($AVDAdminUserCreds.UserName)$AtSign$DomainName"			
		DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		} 	
		
		xADUser FirstUser 
		{ 
		DomainName = $DomainName					
		DomainAdministratorCredential = $DomainCreds 
		UserName = $myFirstUserCreds.UserName
		Password = $myFirstUserCreds
		Ensure = "Present" 
		Path = "OU=AZURE-SYNC,OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
		UserPrincipalName = "$($myFirstUserCreds.UserName)$AtSign$CustomDomainName"
		DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait"		
		}
		
		xADGroup 'g1'
		{
			GroupName           = "$SGAVDHostpoolDAG"
			GroupScope          = 'Global'
			Category			= 'Security'
			Path 				= "OU=AZURE-SYNC,OU=GROUPS,OU=RESOURCES,$DomainDN"
			Description			= 'Group used to grant users access to AVD Hostpool'
			MembershipAttribute = 'DistinguishedName'
			Members             = @(
				"CN=$clearUserTest,OU=AZURE-SYNC,OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
			)
			DependsOn = "[ADOrganizationalUnit]Resources","[xADUser]FirstUser","[xWaitForADDomain]DscForestWait" 
		}
		
		xADGroup 'g2'
		{
			GroupName           = "$SGFSContributorGroups"
			GroupScope          = 'Global'
			Category 			= 'Security'
			Path 				= "OU=AZURE-SYNC,OU=GROUPS,OU=RESOURCES,$DomainDN"
			Description			= 'Group used to grant users access to FSLogix profile location'
			MembershipAttribute = 'DistinguishedName'
			Members             = @(
				"CN=$clearUserAVD,OU=AZURE-SYNC,OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
				"CN=$SGAVDHostpoolDAG,OU=AZURE-SYNC,OU=GROUPS,OU=RESOURCES,$DomainDN"
			)
			DependsOn = "[xADUser]AVDAdmin", "[xADGroup]g1", "[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		
		xADGroup 'g3'
		{
			GroupName           = "$SGFSEleContributorGroups"
			GroupScope          = 'Global'
			Category 			= 'Security'
			Path 				= "OU=AZURE-SYNC,OU=GROUPS,OU=RESOURCES,$DomainDN"
			Description			= 'Group used to grant file admins access to FSLogix profile location'
			MembershipAttribute = 'DistinguishedName'
			Members             = @(
				"CN=$clearUserAVD,OU=AZURE-SYNC,OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"    
				)
			DependsOn = "[xADUser]AVDAdmin", "[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		
		xADGroup 'g4'
		{
			GroupName           = "$SGAVDLocalAdmins"
			GroupScope          = 'Global'
			Category 			= 'Security'
			Path 				= "OU=NO-SYNC,OU=GROUPS,OU=RESOURCES,$DomainDN"
			Description			= 'Group used to grant localadmin permissions and deny avd policies to avd admin accounts'
			MembershipAttribute = 'DistinguishedName'
			Members             = @(
				"CN=$clearUserAVD,OU=AZURE-SYNC,OU=USERACCOUNTS,OU=ACCOUNTS,OU=RESOURCES,$DomainDN"
			)
			DependsOn = "[xADUser]AVDAdmin", "[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
				
			
		ADKDSKey KDSRootKeyInPast
		{
			Ensure = 'Present'
			EffectiveTime = '6/6/2022 13:00'
			AllowUnsafeEffectiveTime = $true # Use with caution
		}
		
		xADRecycleBin RecycleBin
        {
            # Credential with Enterprise Administrator rights to the forest.
            EnterpriseAdministratorCredential = $AdminCreds
            # Fully qualified domain name of forest to enable Active Directory Recycle Bin.
            ForestFQDN                        = $DomainName
            DependsOn                         = "[xWaitForADDomain]DscForestWait"
        }
		
		xRemoteFile Az {
		Uri			    = "https://github.com/Azure/azure-powershell/releases/download/v10.1.0-July2023/Az-Cmdlets-10.1.0.37441-x64.msi"
		DestinationPath = "C:\temp\AVDDSC\Az-Cmdlets-10.1.0.37441-x64.msi"		
		MatchSource     = $false
		}
		
		xRemoteFile Newtonsoft {
		Uri			    = "$RemoteDSCRepo$dlNewtonsoft"
		DestinationPath = "C:\temp\AVDDSC\Newtonsoft.Json.dll"		
		MatchSource     = $false
		}
		
		xRemoteFile admx {
		Uri			    = "$RemoteDSCRepo$dlADMX"
		DestinationPath = "C:\temp\AVDDSC\admx.zip"		
		MatchSource     = $false
		}
		
		xRemoteFile fslogix {
		Uri			    = "$RemoteDSCRepo$dlFSLOGIX"
		DestinationPath = "C:\temp\AVDDSC\redirections.xml"	
		MatchSource     = $false
		}
		
		xRemoteFile aadconnect {
		Uri			    = "$RemoteDSCRepo$dlAADC"
		DestinationPath = "C:\temp\AVDDSC\AADConnectProvisioningAgentSetup.exe"	
		MatchSource     = $false
		}
		
		xRemoteFile storageaccount {
		Uri			    = "$RemoteDSCRepo$dlSAjoin"
		DestinationPath = "C:\temp\AVDDSC\JoinStorageAccountToDomain.ps1"	
		MatchSource     = $false
		}
		
		xRemoteFile AVDGPOs {
		Uri			    = "$RemoteDSCRepo$dlAVDGPOs"
		DestinationPath = "C:\temp\AVDDSC\AVDGPOs.zip"	
		MatchSource     = $false
		}
		
		xRemoteFile DL-AADC {
		Uri			    = "$RemoteDSCRepo$DLLAADC"
		DestinationPath = "C:\temp\AVDDSC\MAADC.zip"	
		MatchSource     = $false
		}	

		Archive DL-AADC {
		Ensure = "Present"
		Path = "C:\temp\AVDDSC\MAADC.zip"
		Destination = "C:\temp\AVDDSC"
		DependsOn = "[xRemoteFile]DL-AADC"
		}		
		
		Archive admx {
		Ensure = "Present"
		Path = "C:\temp\AVDDSC\admx.zip"
		Destination = "c:\windows\PolicyDefinitions"
		DependsOn = "[xRemoteFile]admx"
		}
		
		Archive avdgpo {
		Ensure = "Present"
		Path = "C:\temp\AVDDSC\AVDGPOs.zip"
		Destination = "C:\temp\AVDDSC\AVDGPOs"
		DependsOn = "[xRemoteFile]AVDGPOs"
		}
		
		Archive avdgpotools {
		Ensure = "Present"
		Path = "C:\Temp\AVDDSC\AVDGPOs\GPOTools-development.zip"
		Destination = "C:\temp"
		DependsOn = "[Archive]avdgpo"
		}
		
		File DirectoryCopy
        {	#Create central store
            Ensure = "Present" # Ensure the directory is Present on the target node.
            Type = "Directory" # The default is File.
            Recurse = $true # Recursively copy all subdirectories.
            SourcePath = "c:\windows\PolicyDefinitions" 
            DestinationPath = "\\$DomainName\SYSVOL\$DomainName\Policies\PolicyDefinitions"
			MatchSource     = $false
			DependsOn = "[Archive]admx"
        }			
		
		File fslogixredir
        {
            Ensure = "Present" # Ensure the directory is Present on the target node.
            Type = "File" # The default is File.
            Recurse = $true # Recursively copy all subdirectories.
            SourcePath = "C:\temp\AVDDSC\redirections.xml" 
            DestinationPath = "\\$DomainName\NETLOGON\AVD\redirections.xml"
			MatchSource     = $false
			DependsOn = "[xRemoteFile]fslogix"
        }	
		
		#Creating the AzFiles.json:
		JsonFile SubscriptionId
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'SubscriptionId'
			Value = "$SubscriptionId"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile TenantId
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'TenantId'
			Value = "$TenantId"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
				
		JsonFile ResourceGroupName
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'ResourceGroupName'
			Value = "$ResourceGroupName"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}		
		
		JsonFile StorageAccountName
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'StorageAccountName'
			Value = "$StorageAccountName"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile ShareName
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'ShareName'
			Value = "$ShareName"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile DomainAccountType
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'DomainAccountType'
			Value = "$DomainAccountType"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile OU
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'OU'
			Value = "$OU$DomainDN"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile EncryptionType
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'EncryptionType'
			Value = "$EncryptionType"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile SGAVDHostpoolDAG
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'SGAVDHostpoolDAG'
			Value = "$SGAVDHostpoolDAG"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile FSContributorGroups
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'SGFSContributorGroups'
			Value = "$SGFSContributorGroups"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile FSEleContributorGroups
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'SGFSEleContributorGroups'
			Value = "$SGFSEleContributorGroups"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile FSAdminUsers
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'FSAdminUsers'
			Value = "$FSAdminUsers"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile DownloadUrl
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'DownloadUrl'
			Value = "$DownloadUrl"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile ModulePath
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'ModulePath'
			Value = "$ModulePath"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}
		
		JsonFile DriveLetter
		{
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'DriveLetter'
			Value = "$DriveLetter"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
		}

		JsonFile DCNameJson
		{
			
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'DCName'
			Value = "$DCName"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
					
			
		}
		
		JsonFile DomainDN
		{
			
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'DomainDN'
			Value = "$DomainDN"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
					
			
		}
		
		JsonFile AVDHostRange
		{
			
			Path = 'C:\temp\AVDDSC\AZFiles.json'
			Key = 'AVD0hostIP'
			Value = "$AVD0hostIP"
			DependsOn = "[ADForestProperties]Configuration","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait" 
					
			
		}
		
		
		
        Log AfterDirectoryCopy
        {
            # The message below gets written to the Microsoft-Windows-Desired State Configuration/Analytic log
            Message = "Finished running the file resource with ID DirectoryCopy"
            DependsOn = "[File]DirectoryCopy","[File]fslogixredir" # Depends on successful execution of the File resource.
        }
		
		#Set Time Zone:
			Set-TimeZone -Id "W. Europe Standard Time"
 
		#Set NTP server and VMIC:
			reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w32time\TimeProviders\VMICTimeProvider /v Enabled /t REG_DWORD /d 1 /f
			reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w32time\TimeProviders\NtpClient /v Enabled /t REG_DWORD /d 0 /f
			
			
		xPendingReboot Reboot1
        { 
            Name = "RebootServer"
            DependsOn = '[xWaitForADDomain]DscForestWait', '[ADOrganizationalUnit]AZURE-NOSYNC-U', '[Log]AfterDirectoryCopy'	
			
        }
				
	   Script InstallAz
       {
           GetScript = 
           {
               Return $@{}
           }
	   
           SetScript =
           {
				$AVD0hostIP1 = $using:AVD0hostIP				
			   
			  Enable-PSRemoting -Force
			  winrm quickconfig -force
			  Set-Item wsman:localhost\client\trustedhosts -value $AVD0hostIP1 -force
              Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\AVDDSC\Az-Cmdlets-10.1.0.37441-x64.msi /quiet'
           }
	   
           TestScript =
           {
               Return $false
           }
	  		DependsOn =  "[xPendingReboot]Reboot1","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait","[xADGroup]g1","[xADGroup]g2","[xADGroup]g3","[xADGroup]g4","[xRemoteFile]Az"
        }

		Script AADC
        {
           GetScript = 
           {
               Return $@{}
           }
	   
           SetScript =
           {
			  if (Test-Path HKLM:\SOFTWARE\AADC_Status\)
				{}
				else
				{
					if (Test-Path C:\Temp\AADC_Installation.txt) 
					{
						Remove-Item -Force C:\Temp\AADC_Installation.txt
					} 
					else
					{
					$date = get-date 
					$appendlog = "$date -- HKLM Key not found; Starting AADC script..."
					$appendlog | Out-File -Append "c:\temp\AADC_Installation.txt"
					
					}
					
				  $installerProcess = Start-Process 'c:\temp\AVDDSC\AADConnectProvisioningAgentSetup.exe' /quiet -NoNewWindow -PassThru 
				  $installerProcess.WaitForExit()
				  Import-Module "C:\Program Files\Microsoft Azure AD Connect Provisioning Agent\Microsoft.CloudSync.PowerShell.dll"
				  Import-module "C:\Program Files\Microsoft Azure AD Connect Provisioning Agent\Utility\AADCloudSyncTools"
				  Install-AADCloudSyncToolsPrerequisites			  
				  
				  $DomainName2 = $using:DomainName			
				  $clearUserAzure1 = $using:clearUserAzure
				  $clearPassAzure1 = Unprotect-CmsMessage -Content $using:clearPassAzure 
				  $clearUserAdmin1 = $using:clearUserAdmin
				  $clearPassAdmin1 = Unprotect-CmsMessage -Content $using:clearPassAdmin
				   
				  $User1 = $clearUserAzure1
				  $PWord1 = ConvertTo-SecureString -String $clearPassAzure1 -AsPlainText -Force
				  $Credential1 = New-Object System.Management.Automation.PSCredential($User1,$PWord1)
				  
				  $User2 = $clearUserAdmin1
				  $PWord2 = ConvertTo-SecureString -String $clearPassAdmin1 -AsPlainText -Force
				  $Credential2 = New-Object System.Management.Automation.PSCredential($User2,$PWord2)
				  
				  Connect-AADCloudSyncAzureAD -Credential $Credential1
				  Add-AADCloudSyncGMSA -Credential $Credential2
				  Copy-Item C:\Temp\AVDDSC\Newtonsoft.Json.dll "C:\Program Files\Microsoft Azure AD Connect Provisioning Agent\Newtonsoft.Json.dll" -Force
				  Add-AADCloudSyncADDomain -DomainName $DomainName2 -Credential $Credential2
				  Copy-Item "C:\Program Files\Microsoft Azure AD Connect Provisioning Agent\RegistrationPowershell\Newtonsoft.Json.dll" "C:\Program Files\Microsoft Azure AD Connect Provisioning Agent\Newtonsoft.Json.dll" -Force
			
				  Restart-Service -Name AADConnectProvisioningAgent 


				$ErrorOccured1 = $false
				do
					{
						try 
							{
								$SSPR = Set-AADCloudSyncPasswordWritebackConfiguration -Enable $true -Credential $Credential1 -ErrorAction Ignore	
								"$SSPR" | out-file "c:\temp\SSPR.txt" -Append
								$ErrorOccured1 = $false
							}
						catch 
							{
							$ErrorOccured1 = $true
							"Retrying SSPR..." | out-file "c:\temp\SSPR.txt" -Append
							Start-Sleep 5 
							
							#$SSPR = Set-AADCloudSyncPasswordWritebackConfiguration -Enable $true -Credential $Credential1 -ErrorAction SilentlyContinue 	
							"$SSPR" | out-file "c:\temp\SSPR.txt" -Append
							}
					}
					while ($ErrorOccured1 -eq $true)
				  
				 
				 
					
				  $date = get-date 
				  $appendlog = "$date -- Starting AADC Sync validation..."
				  $appendlog | Out-File -Append "c:\temp\AADC_Installation.txt"
				  
				  $clearUserAVD = $using:clearUserAVD
				  $AtSign = $using:AtSign
				  $AADTenantName  = $using:AADTenantName
				  $AVDUserPrincipalName = "$clearUserAVD$AtSign$AADTenantName"
				  Connect-AzAccount -Credential $Credential1
				  Get-AzContext | Out-File -Append "c:\temp\AADC_Installation.txt"
				  
			      $ErrorOccured = $false
					do
						{
							try 
							{
								# Test for the existence of the AVD admin account in Azure AD to verify that AAD Cloud Sync is functional
								if($AVDUserPrincipalName){
									$AVDUserPrincipalName = $AVDUserPrincipalName.ToString()
									$azureaduser = Get-AzADUser -UserPrincipalName $AVDUserPrincipalName -ErrorAction Stop 
									$date = get-date 
									$appendlog = "$date -- $azureaduser --- Output from AzureADUser:"
									$appendlog | Out-File -Append "c:\temp\AADC_Installation.txt"
									   #check if something found    
									   if($azureaduser){
											$date = get-date                                
                                            $appendlog = "$date -- User $AVDUserPrincipalName is replicated to Azure... continuing DSC."
                                            $appendlog | Out-File -Append "c:\temp\AADC_Installation.txt"
											 }
											 else{
												 #running a bogus command to create an error, triggering the catch.
												 get-dummy
												 
											 #Write-Host "User $AVDUserPrincipalName was not found in $displayname Azure AD " -ForegroundColor Red
											 #return $false
									   }
								}
								$ErrorOccured = $false
							}
							catch 
							{
							   
								$date = get-date                                
                                $appendlog = "$date -- User $AVDUserPrincipalName doesn't exist in Azure yet ... retrying in 30 seconds..."
                                $appendlog | Out-File -Append "c:\temp\AADC_Installation.txt"
                                
                                  
								$ErrorOccured = $true
								Start-Sleep 30 
								$azureaduser = Get-AzADUser -UserPrincipalName $AVDUserPrincipalName 
								$date = get-date 
								$appendlog = "$date -- $azureaduser --- Output from AzureADUser:"
								$appendlog | Out-File -Append "c:\temp\AADC_Installation.txt"
								
									   
							}
						}
					while ($ErrorOccured -eq $true)
                               	$date = get-date                                
                                $appendlog = "$date -- User $AVDUserPrincipalName is replicated to Azure... continuing DSC."
                                $appendlog | Out-File -Append "c:\temp\AADC_Installation.txt" 
			

							New-Item -Path HKLM:\SOFTWARE\AADC_Status
							New-ItemProperty -Path HKLM:\SOFTWARE\AADC_Status -Name AADC_Installed -Value "DON'T REMOVE! Required for correct DSC rerun of AADC installation."		


							
			}
		   }
	   
           TestScript =
           {
               Return $false
           }
	  		DependsOn =  "[xRemoteFile]Newtonsoft","[xPendingReboot]Reboot1","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait","[xADGroup]g1","[xADGroup]g2","[xADGroup]g3","[xADGroup]g4","[xRemoteFile]aadconnect"
        }	
		
 
 	Script CreateGPO
  {
 		  GetScript = 
      {
          Return $@{}
      }
    
      SetScript =
      {		
 			
 
 
 			Install-Module GPOTools -Force
			Import-Module GPOTools
 			#Backup-GptPolicy -Path C:\Temp\AVDDSC\GPOBackup
			$domaininfo = Get-ADDomain
			$dcinfo = Get-ADDomainController
			
			$DomainFQDNNEW = $domaininfo.DNSRoot	
			$DomainDNNEW = $domaininfo.DistinguishedName
			$DomainNetBIOSNEW = $domaininfo.NetBIOSName
			$DomainSIDNEW = $domaininfo.DomainSID | Select-Object -ExpandProperty "Value"
			$DomainGUIDNEW = $domaininfo.ObjectGUID
			$DCNameNEW = $dcinfo.Name			
			
			$SGAVDLocalAdminsNEW = $using:SGAVDLocalAdmins
			$SGCavd = Get-ADGroup -Identity $SGAVDLocalAdminsNEW
			$SGCavdRID = $SGCavd.SID | Select-Object -ExpandProperty "Value"
			$SGCavdRID1 = $SGCavdRID.Replace($DomainSIDNEW+'-','')
			$SGAVDLocalAdminsRIDNEW = $SGCavdRID1			
			
			$SGAVDHostpoolDAGNEW = $using:SGAVDHostpoolDAG
			$SGCDAG = Get-ADGroup -Identity $SGAVDHostpoolDAGNEW
			$SGCDAGRID = $SGCDAG.SID | Select-Object -ExpandProperty "Value"
			$SGCDAGRID1 = $SGCDAGRID.Replace($DomainSIDNEW+'-','')		
			$SGAVDHostpoolDAGRIDNEW = $SGCDAGRID1			
			
			$SGFSContributorGroupsNEW = $using:SGFSContributorGroups
			$SGCont = Get-ADGroup -Identity $SGFSContributorGroupsNEW
			$SGContRID = $SGCont.SID | Select-Object -ExpandProperty "Value"
			$SGContRID1 = $SGContRID.Replace($DomainSIDNEW+'-','')
			$SGFSContributorGroupsRIDNEW = $SGContRID1
			
			$SGFSEleContributorGroupsNEW = $using:SGFSEleContributorGroups
			$SGCEle = Get-ADGroup -Identity $SGFSEleContributorGroupsNEW
			$SGCEleRID = $SGCEle.SID | Select-Object -ExpandProperty "Value"
			$SGCEleRID1 = $SGCEleRID.Replace($DomainSIDNEW+'-','')	
			$SGFSEleContributorGroupsRIDNEW = $SGCEleRID1			
			
			$AVDAdminUserCredsNEW = $using:clearUserAVD
			$DomainAdminUsernameNEW = $using:clearUserAdmin
			$TenantIDNEW = $using:TenantID
			$SANameNEW = $using:StorageAccountName
			$FSLogixShareNameNEW = $using:ShareName			
			
			$GetGPOVariables = @()
 			$GetGPOVariablesMig = @()
 			$GetGPOValues = @()
 			
 			$GetGPOVariables += "{DomainFQDN}"
 			$GetGPOVariables += "{DomainDN}"
 			$GetGPOVariables += "{DomainNetBIOS}"
 			$GetGPOVariables += "{DomainSID}"
 			$GetGPOVariables += "{DomainGUID}"
 			$GetGPOVariables += "{DCName}"
 			$GetGPOVariables += "{SGAVDLocalAdmins}"
 			$GetGPOVariables += "{SGAVDLocalAdminsRID}"
 			$GetGPOVariables += "{SGAVDHostpoolDAG}"
 			$GetGPOVariables += "{SGAVDHostpoolDAGRID}"
 			$GetGPOVariables += "{SGFSContributorGroups}"
 			$GetGPOVariables += "{SGFSContributorGroupsRID}"
 			$GetGPOVariables += "{SGFSEleContributorGroups}"
 			$GetGPOVariables += "{SGFSEleContributorGroupsRID}"
 			$GetGPOVariables += "{AVDAdminUserCreds}"
 			$GetGPOVariables += "{DomainAdminUsername}"
 			$GetGPOVariables += "{TenantID}"
 			$GetGPOVariables += "{SAName}"
 			$GetGPOVariables += "{FSLogixShareName}"
 			
 			$GetGPOVariablesMig += "{DomainFQDNNEW}"
 			$GetGPOVariablesMig += "{DomainDNNEW}"
 			$GetGPOVariablesMig += "{DomainNetBIOSNEW}"
 			$GetGPOVariablesMig += "{DomainSIDNEW}"
 			$GetGPOVariablesMig += "{DomainGUIDNEW}"
 			$GetGPOVariablesMig += "{DCNameNEW}"
 			$GetGPOVariablesMig += "{SGAVDLocalAdminsNEW}"
 			$GetGPOVariablesMig += "{SGAVDLocalAdminsRIDNEW}"
 			$GetGPOVariablesMig += "{SGAVDHostpoolDAGNEW}"
 			$GetGPOVariablesMig += "{SGAVDHostpoolDAGRIDNEW}"
 			$GetGPOVariablesMig += "{SGFSContributorGroupsNEW}"
 			$GetGPOVariablesMig += "{SGFSContributorGroupsRIDNEW}"
 			$GetGPOVariablesMig += "{SGFSEleContributorGroupsNEW}"
 			$GetGPOVariablesMig += "{SGFSEleContributorGroupsRIDNEW}"
 			$GetGPOVariablesMig += "{AVDAdminUserCredsNEW}"
 			$GetGPOVariablesMig += "{DomainAdminUsernameNEW}"
 			$GetGPOVariablesMig += "{TenantIDNEW}"
 			$GetGPOVariablesMig += "{SANameNEW}"
 			$GetGPOVariablesMig += "{FSLogixShareNameNEW}"
 			
 			$GetGPOValues += $DomainFQDNNEW #"TESTCORP.LOCAL" # {DomainFQDNNEW}
 			$GetGPOValues += $DomainDNNEW # "DC=TESTCORP,DC=LOCAL" # {DomainDNNEW}
 			$GetGPOValues += $DomainNetBIOSNEW # "TESTCORP" # {DomainNetBIOSNEW}
 			$GetGPOValues += $DomainSIDNEW # "S-1-5-21-952498549-1393490378-1622504466" # {DomainSIDNEW}
 			$GetGPOValues += $DomainGUIDNEW # "dfbf6890-9947-482e-b2e1-4346fb2aeb46" # {DomainGUIDNEW}
 			$GetGPOValues += $DCNameNEW # "WOWSRVDC00" # {DCNameNEW}
 			$GetGPOValues += $SGAVDLocalAdminsNEW # "WOW-SG-AVD-LocalAdmins" # {SGAVDLocalAdminsNEW}
 			$GetGPOValues += $SGAVDLocalAdminsRIDNEW # "1108" # {SGAVDLocalAdminsRIDNEW}
 			$GetGPOValues += $SGAVDHostpoolDAGNEW # "WOW-SG-AVD-Hostpool-DAG" # {SGAVDHostpoolDAGNEW}
 			$GetGPOValues += $SGAVDHostpoolDAGRIDNEW # "1105" # {SGAVDHostpoolDAGRIDNEW}
 			$GetGPOValues += $SGFSContributorGroupsNEW # "WOW-SG-AVD-FSLogix Share Contributor" # {SGFSContributorGroupsNEW}
 			$GetGPOValues += $SGFSContributorGroupsRIDNEW # "1106" # {SGFSContributorGroupsRIDNEW}
 			$GetGPOValues += $SGFSEleContributorGroupsNEW # "WOW-SG-AVD-FSLogix Share Elevated Contributor" # {SGFSEleContributorGroupsNEW}
 			$GetGPOValues += $SGFSEleContributorGroupsRIDNEW # "1107" # {SGFSEleContributorGroupsRIDNEW}
 			$GetGPOValues += $AVDAdminUserCredsNEW # "WOWAVDLocalAdmin" # {AVDAdminUserCredsNEW}
 			$GetGPOValues += $DomainAdminUsernameNEW # "WOWADAdmin" # {DomainAdminUsernameNEW}
 			$GetGPOValues += $TenantIDNEW # "3391b5b0-7a1e-4a54-ae8c-b7c2da250e32" # {TenantIDNEW}
 			$GetGPOValues += $SANameNEW # "ntsfslogixsa" # {SANameNEW}
 			$GetGPOValues += $FSLogixShareNameNEW # "fslogixfilesnts" # {FSLogixShareNameNEW}
			
			$date = get-date  
			$appendlog = "$date -- Using GPO Variable Values: --"
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 			
            $appendlog = "-- DomainFQDNNEW = $DomainFQDNNEW ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 		
			$appendlog = "-- DomainDNNEW = $DomainDNNEW ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- DomainNetBIOSNEW = $DomainNetBIOSNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- DomainSIDNEW = $DomainSIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- DomainGUIDNEW = $DomainGUIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- DCNameNEW = $DCNameNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGAVDLocalAdminsNEW = $SGAVDLocalAdminsNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGAVDLocalAdminsRIDNEW = $SGAVDLocalAdminsRIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGAVDHostpoolDAGNEW = $SGAVDHostpoolDAGNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGAVDHostpoolDAGRIDNEW = $SGAVDHostpoolDAGRIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGFSContributorGroupsNEW = $SGFSContributorGroupsNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGFSContributorGroupsRIDNEW = $SGFSContributorGroupsRIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGFSEleContributorGroupsNEW = $SGFSEleContributorGroupsNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SGFSEleContributorGroupsRIDNEW = $SGFSEleContributorGroupsRIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- AVDAdminUserCredsNEW = $AVDAdminUserCredsNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- DomainAdminUsernameNEW = $DomainAdminUsernameNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- TenantIDNEW = $TenantIDNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- SANameNEW = $SANameNEW  ..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			$appendlog = "-- FSLogixShareNameNEW = $FSLogixShareNameNEW  ..."		
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			
			  
			
			 if (Test-Path HKLM:\SOFTWARE\GPO_Status\)
				{}
				else
				{
					
					$appendlog = "$date -- Changing GPO values..."
					$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
					$GPOs = Get-ChildItem -Path C:\Temp\AVDDSC\AVDGPOs\GPOBackup\*.* -Recurse -Force -Exclude *.pol, gpreport.*, *.migtable
					foreach ($gpo in $GPOs)
					{
						$i = 0
					
							for($i = 0; $i -lt $GetGPOValues.Count; $i++)    {
							 
								((Get-Content $gpo) -replace $GetGPOVariables[$i],$GetGPOValues[$i] | Set-Content $gpo)        
								
					
							}
							   
					
					}
					
					$GPOs = Get-ChildItem -Path C:\Temp\AVDDSC\AVDGPOs\GPOBackup\*.* -Recurse -Force -Filter gpreport.*
					foreach ($gpo in $GPOs)
					{
						$i = 0
					
							for($i = 0; $i -lt $GetGPOValues.Count; $i++)    {
							 
								((Get-Content $gpo) -replace $GetGPOVariables[$i],$GetGPOValues[$i] | Set-Content -Encoding unicode $gpo )        
								
					
							}
							   
					
					}
					
					$GPOs = Get-ChildItem -Path C:\Temp\AVDDSC\AVDGPOs\GPOBackup\*.* -Recurse -Force -Filter *.migtable
					foreach ($gpo in $GPOs)
					{
						$i = 0
					
							for($i = 0; $i -lt $GetGPOValues.Count; $i++)    {
							 
								((Get-Content $gpo) -replace $GetGPOVariablesMig[$i],$GetGPOValues[$i] | Set-Content -Encoding unicode $gpo ) 
								((Get-Content $gpo) -replace $GetGPOVariables[$i],$GetGPOValues[$i] | Set-Content -Encoding unicode $gpo )          
								
					
							}
							   
					
					}
		 
					$appendlog = "$date -- Renaming GPO files..."
					$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
					$DefaultFiles =  Get-ChildItem -path C:\Temp\AVDDSC\AVDGPOs\GPOBackup -Recurse | Where-Object {$_.Name -like "*{DomainFQDN}*"}
					ForEach($File in $DefaultFiles) 
					{
						$newname = ([String]$File).Replace("{DomainFQDN}",$DomainFQDNNEW)
						Rename-item -Path $File.PSPath $newname
					}
					
					New-Item -Path HKLM:\SOFTWARE\GPO_Status
					New-ItemProperty -Path HKLM:\SOFTWARE\GPO_Status -Name GPO_Configured -Value "DON'T REMOVE! Required for correct DSC rerun of GPO configuration."
					
				}
 
     }
   
     TestScript =
     {
         Return $false
     }
  		DependsOn =  "[xPendingReboot]Reboot1","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait","[xADGroup]g1","[xADGroup]g2","[xADGroup]g3","[xADGroup]g4","[Archive]AVDGPO"
  }
 
 	Script ConfigureGPO
  {
 		  GetScript = 
      {
          Return $@{}
      }
    
      SetScript =
      {		
	  
			$domaininfo = Get-ADDomain
			$DomainFQDNNEW = $domaininfo.DNSRoot	
			$Domain = $using:DomainFQDNNEW
			$DomainDNNEW = $domaininfo.DistinguishedName
			$TenantIDNEW = $using:TenantID
			$SANameNEW = $using:StorageAccountName
			$FSLogixShareNameNEW = $using:ShareName	
			$SGAVDLocalAdminsNEW = $using:SGAVDLocalAdmins
			
			$date = get-date                                
            $appendlog = "$date -- Installing GPOTools Module..."
            $appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
 			Install-Module GPOTools -Force
			
			$date = get-date                                
            $appendlog = "$date -- Importing GPOTools Module..."
            $appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Import-Module GPOTools 
			
			$date = get-date                                
            $appendlog = "$date -- Restoring GPO's..."
            $appendlog | Out-File -Append "c:\temp\GPO_Installation.txt"  			 	
			
			$date = get-date                                
            $appendlog = "$date -- Domain is $Domain..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 			
			
			$date = get-date                                
            $appendlog = "$date -- Starting Base import + link..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			
			C:\Temp\AVDDSC\AVDGPOs\Import_GPOs.ps1 -SomInfo -Domain $DomainFQDNNEW -BackupFolder C:\Temp\AVDDSC\AVDGPOs\GPOBackup\base | Out-File -Append "c:\temp\GPO_Installation.txt" 
			New-GPLink -Name "Delta Domain Policy" -Target $DomainDNNEW -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-File -Append "c:\temp\GPO_Installation.txt" 
		
			$date = get-date                                
            $appendlog = "$date -- Setting FSLogix OfficeContainer VHD locations..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Set-GPRegistryValue -Name "C-Azure Virtual Desktop - FSLogix Settings" -Key "HKEY_LOCAL_MACHINE\Software\Policies\FSLogix\ODFC" -ValueName "VHDLocations" -Type String -Value "\\$SANameNEW.file.core.windows.net\$FSLogixShareNameNEW"
			
			$date = get-date                                
            $appendlog = "$date -- Setting FSLogix VHD locations..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Set-GPRegistryValue -Name "C-Azure Virtual Desktop - FSLogix Settings" -Key "HKEY_LOCAL_MACHINE\Software\FSLogix\Profiles" -ValueName "VHDLocations" -Type String -Value "\\$SANameNEW.file.core.windows.net\$FSLogixShareNameNEW"
			
			$date = get-date                                
            $appendlog = "$date -- Setting FSLogix XML Redirection..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Set-GPRegistryValue -Name "C-Azure Virtual Desktop - FSLogix Settings" -Key "HKEY_LOCAL_MACHINE\Software\FSLogix\Profiles" -ValueName "RedirXMLSourceFolder" -Type String -Value "\\$DomainFQDNNEW\NETLOGON\AVD"
			
			$date = get-date                                
            $appendlog = "$date -- Setting OneDrive TenantID..."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Set-GPRegistryValue -Name "LR-Azure Virtual Desktop - Host Settings" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\OneDrive" -ValueName "KFMSilentOptIn" -Type String -Value $TenantIDNEW

			$date = get-date                                
            $appendlog = "$date -- Setting Deny Apply to Domain Admins and $SGAVDLocalAdminsNEW for ""LR-Azure Virtual Desktop - Host Settings"" policy ."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Import-module "C:\Temp\AVDDSC\AVDGPOs\Set-GPPermissionDeny.ps1" -Force		
			Set-GPPermission -Name "LR-Azure Virtual Desktop - Host Settings" -TargetName "$SGAVDLocalAdminsNEW" -TargetType Group -PermissionLevel GpoRead			
			Set-GPPermissionDeny -GroupName "Domain Admins" -GpoName "LR-Azure Virtual Desktop - Host Settings" | Out-File -Append "c:\temp\GPO_Installation.txt" 
			Set-GPPermissionDeny -GroupName "$SGAVDLocalAdminsNEW" -GpoName "LR-Azure Virtual Desktop - Host Settings" | Out-File -Append "c:\temp\GPO_Installation.txt" 
			
			$date = get-date                                
            $appendlog = "$date -- Finished creating and configuring GPO's."
			$appendlog | Out-File -Append "c:\temp\GPO_Installation.txt" 
			
			Start-Sleep -Seconds 5
			Restart-NetAdapter -Name Ethernet
 
     }
   
     TestScript =
     {
         Return $false
     }
  		DependsOn =  "[xPendingReboot]Reboot1","[ADOrganizationalUnit]Resources","[xWaitForADDomain]DscForestWait","[xADGroup]g1","[xADGroup]g2","[xADGroup]g3","[xADGroup]g4","[Script]CreateGPO"
  }
 
 

}		
	
	}
	
	