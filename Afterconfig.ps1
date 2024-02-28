#Install Digijust Tracker 1.2

	### VARIABLES
	#[type]$Name = "VALUE"
	[string]$ZipFile = "C:\temp\Digijust Tracker 1.2.zip"
	[string]$DestinationFolder = "C:\Program Files\DigiJust Tracker"
	[string]$Trackerconfig = "C:\Program Files\DigiJust Tracker\DigijustTrackerUri-win32-x64\resources\app\config.json"
	[string]$Replacetext1 = '%HOMEDRIVE%/Applicaties/Digijust/tijdelijkeDigiJustBestanden'
	[string]$Replacetext2 = '%HOMEDRIVE%/AppData/Roaming/Digijust/Logs'
	[string]$Replacetextwith1 = '%userprofile%/documents/Digijust/tijdelijkeDigiJustBestanden'
	[string]$Replacetextwith2 = '%userprofile%/documents/Digijust/logs'
	[string]$RegPAth = "Registry::\HKEY_CLASSES_ROOT\DigiJustUri"
	###
	# Stop script on error
	$ErrorActionPreference = "Stop"

	try
	{
		 #extract zip file
		 Add-Type -A System.IO.Compression.FileSystem
		 [IO.Compression.ZipFile]::ExtractToDirectory($ZipFile, $DestinationFolder)

		 #Custom DWO config.json work and log folder
		 (Get-Content -Path $Trackerconfig).Replace("$Replacetext1", "$Replacetextwith1") | Set-Content -Path $Trackerconfig
		 (Get-Content -Path $Trackerconfig).Replace("$Replacetext2", "$Replacetextwith2") | Set-Content -Path $Trackerconfig
		 
		 #Set HKLM registry
		 New-Item -Path  $RegPAth -Force | Out-Null
		 New-ItemProperty -Path  $RegPAth -Name "(Default)" -Value "DigiJust URI" -PropertyType String -Force | Out-Null
		 New-ItemProperty -Path  $RegPAth -Name "URL Protocol" -Value "" -PropertyType String -Force | Out-Null
		 New-Item -Path  "$RegPAth\DefaultIcon" -Force | Out-Null
		 New-Item -Path  "$RegPAth\\shell\open\command" -Force | Out-Null
		 New-ItemProperty -Path "$RegPAth\\shell\open\command" -Name "(Default)" -Value '"C:\Program Files\DigiJust Tracker\DigijustTrackerUri-win32-x64\DigijustTrackerUri.exe" "%1"' -PropertyType String -Force | Out-Null
	 }
	catch
	{
		  Write-Warning $_.exception.message
		  # Return code equals line number where error occurred
		  if ($Error[0].InvocationInfo.ScriptLineNumber -gt 0) { Exit $Error[0].InvocationInfo.ScriptLineNumber }
		  else { Exit 1 }
	}





#Disable CoPilot, Fix Taskbar & OneDrive						
REG LOAD HKLM\Default C:\Users\Default\NTUSER.DAT						

#Create Keys
$result1 = New-Item -Path HKLM:\Default\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot -Force
$result1.Handle.Close()

$result2 = New-Item -Path HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Force
$result2.Handle.Close()

$result3 = New-Item -Path HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved -Force
$result3.Handle.Close()

$result4 = New-Item -Path HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run -Force	
$result4.Handle.Close()
						
$result5 = New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Force
$result5.Handle.Close()

$result6 = New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Force
$result6.Handle.Close()						

# Removes Task View from the Taskbar
New-itemproperty -Path HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Value "0" -PropertyType Dword -force

# Removes Widgets from the Taskbar
New-itemproperty -Path HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarDa -Value "0" -PropertyType Dword -force

# Removes Chat from the Taskbar
New-itemproperty -Path HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarMn -Value "0" -PropertyType Dword -force

# Default StartMenu alignment 0=Left
New-itemproperty -Path HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarAl -Value "0" -PropertyType Dword -force
 
# Removes search from the Taskbar					
New-itemproperty -Path HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Value "0" -PropertyType Dword -force

# Remove Context Menu from Start Menu
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
New-itemproperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableContextMenusInStart -Value "1" -PropertyType Dword -force	

# Remove Network Icon from Explorer
#New-itemproperty -Path 'Registry::HKEY_CLASSES_ROOT\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder' -Name Attributes -Value "b0940064" -PropertyType Dword -force

# Disable Windows 11 Co-Pilot 						
New-itemproperty -Path HKLM:\Default\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot -Name TurnOffWindowsCopilot -Value "1" -PropertyType Dword -force
						
 
# Fix OneDrive
New-itemproperty -Path HKLM:\Default\SOFTWARE\Microsoft\OneDrive -Name PreSignInRampOverrides -Value "1559" -PropertyType Dword -force						
New-itemproperty -Path HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run -Name OneDrive -Value ([byte[]](02,00,00,00,00,00,00,00,00,00,00,00)) -PropertyType Binary -force
New-itemproperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value "0" -PropertyType Dword -force
New-itemproperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSync -Value "0" -PropertyType Dword -force
New-itemproperty -Path HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name OneDrive -Value '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' -PropertyType String -force					

						
#Cleanup variables
Get-Variable result* | remove-variable						

[gc]::collect()
Start-Sleep -Seconds 5
REG UNLOAD HKLM\Default

#Create JAVA exception:
New-Item -ItemType Directory -Force -Path "C:\Users\default\AppData\LocalLow\Sun\Java\Deployment\security"
New-Item -ItemType File -Force -Path "C:\Users\default\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites"
$site1 = "https://ebs.leonardo.minjenv.nl"
$site2 = "https://ebs-acc.leonardo.minjenv.nl"
$site3 = "http://ebs.leonardo.minjenv.nl"
$site4 = "http://ebs-acc.leonardo.minjenv.nl"
Add-Content -Path "C:\Users\default\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$site1"
Add-Content -Path "C:\Users\default\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$site2"
Add-Content -Path "C:\Users\default\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$site3"
Add-Content -Path "C:\Users\default\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$site4"

##Remove bloat
$Bloatware = @(

	#Unnecessary Windows 10/11 AppX Apps
	"Microsoft.549981C3F5F10"
	"Microsoft.BingNews"
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	"Microsoft.Messaging"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.NetworkSpeedTest"
	"Microsoft.MixedReality.Portal"
	"Microsoft.News"
	"Microsoft.Office.Lens"
	"Microsoft.Office.OneNote"
	"Microsoft.Office.Sway"
	"Microsoft.OneConnect"
	"Microsoft.People"
	"Microsoft.Print3D"
	"Microsoft.RemoteDesktop"
	"Microsoft.SkypeApp"
	"Microsoft.StorePurchaseApp"
	"Microsoft.Office.Todo.List"
	"Microsoft.Whiteboard"
	"Microsoft.WindowsAlarms"
	#"Microsoft.WindowsCamera"
	"microsoft.windowscommunicationsapps"
	"Microsoft.WindowsFeedbackHub"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsSoundRecorder"
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxApp"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"
	"MicrosoftTeams"
	"Microsoft.YourPhone"
	"Microsoft.XboxGamingOverlay_5.721.10202.0_neutral_~_8wekyb3d8bbwe"
	"Microsoft.GamingApp"
	"Microsoft.Todos"
	"Microsoft.PowerAutomateDesktop"
	"SpotifyAB.SpotifyMusic"
	"Disney.37853FC22B2CE"
	"*EclipseManager*"
	"*ActiproSoftwareLLC*"
	"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
	"*Duolingo-LearnLanguagesforFree*"
	"*PandoraMediaInc*"
	"*CandyCrush*"
	"*BubbleWitch3Saga*"
	"*Wunderlist*"
	"*Flipboard*"
	"*Twitter*"
	"*Facebook*"
	"*Spotify*"
	"*Minecraft*"
	"*Royal Revolt*"
	"*Sway*"
	"*Speed Test*"
	"*Dolby*"
	"*Office*"
	"*Disney*"
	"clipchamp.clipchamp"
	"*gaming*"
	"MicrosoftCorporationII.MicrosoftFamily"
	"C27EB4BA.DropboxOEM"
	"*DevHome*"
	"*Microsoft.BingWeather*"
	"*Microsoft.MicrosoftStickyNotes*"
	#Optional: Typically not removed but you can if you need to for some reason
	#"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
	#"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"							
	#"*Microsoft.MSPaint*"							
	#"*Microsoft.Windows.Photos*"
	#"*Microsoft.WindowsCalculator*"
	#"*Microsoft.WindowsStore*"

)
foreach ($Bloat in $Bloatware) {
	
	Get-AppxPackage -allusers -Name $Bloat| Remove-AppxPackage -AllUsers
	Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online						
}
	get-appxpackage -AllUsers *Clipchamp.Clipchamp* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.BingNews* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.BingWeather* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.GamingApp* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.Paint* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.People* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.PowerAutomateDesktop* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.ScreenSketch* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsCamera* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsStore* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.WindowsTerminal* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Xbox* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.ZuneMusic* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *Microsoft.ZuneVideo* | Remove-AppxPackage -AllUsers
	get-appxpackage -AllUsers *MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage -AllUsers

