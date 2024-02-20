
Import-Module AzureAD
#Create Credentials
$clearPassAzure1 = Unprotect-CmsMessage -Content $using:clearPassAzure 
$User = $using:clearUserAzure
$PWord = ConvertTo-SecureString -String $clearPassAzure1 -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($User,$PWord)

Connect-AzAccount -Credential $Credential
Set-AzContext -Subscription $using:SubscriptionId
Connect-AzureAD -credential $Credential	

#Add $using:SGAVDHostpoolAdmins to local FSLogix Exclude group
"$(get-date) - $env:computername Adding $using:SGAVDHostpoolAdmins to local FSLogix Exclude group "  | out-file c:\temp\AVDSettings.txt -Append						
$i = 0
$admingroup = Get-AzADGroup -DisplayName $using:SGAVDHostpoolAdmins
$user = Get-AzureADGroupMember -ObjectId $admingroup.Id
for ($i =0; $i -lt $user.Count; $i++) {$userprefixes += $user[$i].UserPrincipalName.Split("@")}							
#$userprefix = $user.UserPrincipalName.Split("@")
$members = get-localgroup | get-localgroupmember -ErrorAction Ignore
"$(get-date) - $env:computername Members of Local Administrators: $members"  | out-file c:\temp\AVDSettings.txt -Append						
"$(get-date) - $env:computername Split Members of $using:SGAVDHostpoolAdmins... $userprefixes"  | out-file c:\temp\AVDSettings.txt -Append						
$i = 0
$a = 0
$addFSLogixExcludes = foreach ($member in $members){for ($a =0; $a -lt $userprefixes.Count; $a++){if ($member.Name -ilike "*"+$userprefixes[$a]+"*"){if ($member.Name -ne $null){if ($userprefixes[$a] -ne $null){Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member $member -erroraction Ignore}}}} if ($a -eq $userprefixes.Count) {$a = 0}}		