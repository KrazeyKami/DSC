#Requires -Version 5.1
<#
.SYNOPSIS
Exporteert de lokale hardware-identiteit naar een Windows Autopilot-import-CSV.
.DESCRIPTION
Voor Windows 10/11. Lokaal uitvoeren als administrator (of SYSTEM).
Werkt offline: geen modules, downloads, tenant-login of Graph-rechten nodig.
Leest alleen apparaatdata en schrijft een CSV. Wijzigt geen AD/Entra-join,
Intune-inschrijving, Autopilot-registratie of deploymentprofiel.
Windows Product ID blijft bewust leeg; voor directe Intune-import is dit optioneel.
CSV: komma's, exacte kolomnamen, ASCII (ANSI-compatibel), geen quotes of BOM.
Standaarduitvoer: C:\Autopilot\Autopilot-<computernaam>.csv.
Met -MergeFolder worden losse CSV's in die map samengevoegd (niet recursief).
Identieke dubbele regels worden overgeslagen; conflicten stoppen de export.
Maximaal 500 unieke apparaten per importbestand. Bestaande uitvoer wordt alleen
overschreven met -Force. Bewerk de CSV niet in Excel.
.PARAMETER GroupTag
Optionele Autopilot Group Tag. Gebruik de tag uit het deploymentontwerp.
.PARAMETER AssignedUser
Optionele bestaande Entra-gebruiker (UPN). Wordt niet online geverifieerd.
.PARAMETER OutputFile
Pad naar het CSV-bestand. Mag ook op een USB-stick of share staan.
Gebruik per apparaat een eigen bestand; schrijf niet gelijktijdig naar dezelfde CSV.
.PARAMETER MergeFolder
Map met uitsluitend Autopilot-import-CSV's. Samenvoegen vereist geen administrator.
.EXAMPLE
.\Export-AutopilotImport.ps1
.EXAMPLE
.\Export-AutopilotImport.ps1 -GroupTag 'PILOT' -OutputFile 'E:\Autopilot\LAPTOP01.csv'
.EXAMPLE
.\Export-AutopilotImport.ps1 -MergeFolder 'C:\Autopilot\Verzameld' -OutputFile 'C:\Autopilot\Import.csv'
.NOTES
Gebaseerd op het door Microsoft beschreven hardware-hash- en CSV-formaat:
https://learn.microsoft.com/en-us/autopilot/add-devices
Hardwarebron: Win32_BIOS en MDM_DevDetail_Ext01.DeviceHardwareData.
Na import: Sync, deploymentprofiel toewijzen en profieltoewijzing controleren.
Importeren migreert een bestaande AD-joined laptop niet automatisch. De normale
Autopilot-uitrol volgt tijdens Windows OOBE na de geplande reset/herinstallatie.
#>
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
    [Parameter(ParameterSetName = 'Collect')]
    [string]$GroupTag = '',

    [Parameter(ParameterSetName = 'Collect')]
    [string]$AssignedUser = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'Merge')]
    [ValidateNotNullOrEmpty()]
    [string]$MergeFolder,

    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$columns = @('Device Serial Number', 'Windows Product ID', 'Hardware Hash', 'Group Tag', 'Assigned User')
$rows = New-Object 'System.Collections.Generic.List[object]'
$serials = @{}
$hashes = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)

function Add-ValidatedRow {
    param([string[]]$Values, [string]$Source)

    if ($Values.Count -ne 5) { throw "Ongeldig aantal velden in $Source." }
    for ($i = 0; $i -lt $Values.Count; $i++) {
        if ($Values[$i] -match '[^\x20-\x7E]|[,\"]') {
            throw "Ongeldig CSV-teken in kolom '$($columns[$i])' van $Source. Gebruik ASCII zonder komma's, quotes of regeleinden."
        }
    }
    if ([string]::IsNullOrWhiteSpace($Values[0]) -or [string]::IsNullOrWhiteSpace($Values[2])) {
        throw "Serienummer of hardware-hash ontbreekt in $Source."
    }
    if ($Values[2] -match '\s') { throw "Hardware-hash bevat witruimte in $Source." }
    try { $decoded = [Convert]::FromBase64String($Values[2]) }
    catch { throw "Hardware-hash is geen geldige Base64 in $Source." }
    if ($decoded.Length -eq 0) { throw "Lege hardware-hash in $Source." }
    if ($Values[4] -and $Values[4] -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
        throw "Assigned User is geen geldig UPN-formaat in $Source."
    }

    $line = $Values -join ','
    $serial = $Values[0]
    $hash = $Values[2]
    if ($serials.ContainsKey($serial)) {
        if ($serials[$serial] -cne $line) {
            throw "Conflicterende regels voor serienummer '$serial' in $Source. Controleer hash, Group Tag en gebruiker."
        }
        Write-Verbose "Identieke dubbele regel overgeslagen: $serial"
        return
    }
    if ($hashes.ContainsKey($hash)) { throw "Dezelfde hardware-hash bij verschillende serienummers in $Source." }
    $serials[$serial] = $line
    $hashes[$hash] = $serial
    $rows.Add([pscustomobject]@{ Serial = $serial; Line = $line })
}

try {
    if ($env:OS -ne 'Windows_NT') { throw 'Voer dit script uit op Windows.' }
    if (-not $OutputFile) {
        if ($PSCmdlet.ParameterSetName -eq 'Merge') {
            $OutputFile = 'C:\Autopilot\Autopilot-Import.csv'
        }
        else { $OutputFile = "C:\Autopilot\Autopilot-$($env:COMPUTERNAME).csv" }
    }
    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    if ([IO.Path]::GetExtension($target) -ine '.csv') { throw 'OutputFile moet eindigen op .csv.' }
    if ((Test-Path -LiteralPath $target) -and -not $Force) {
        throw "Uitvoer bestaat al: $target. Kies een ander pad of gebruik -Force."
    }

    if ($PSCmdlet.ParameterSetName -eq 'Merge') {
        if (-not (Test-Path -LiteralPath $MergeFolder -PathType Container)) {
            throw "Map niet gevonden: $MergeFolder"
        }
        $files = @(Get-ChildItem -LiteralPath $MergeFolder -Filter '*.csv' -File |
            Where-Object { $_.FullName -ine $target } | Sort-Object Name)
        if ($files.Count -eq 0) { throw 'Geen bron-CSV-bestanden gevonden (uitvoerbestand is uitgesloten).' }
        foreach ($file in $files) {
            $lines = [IO.File]::ReadAllLines($file.FullName)
            if ($lines.Length -lt 2) { throw "CSV heeft geen apparaatregels: $($file.Name)" }
            $header = $lines[0].Split([char]',')
            if ($header.Count -lt 3 -or $header.Count -gt 5 -or
                ($header -join ',') -cne ($columns[0..($header.Count - 1)] -join ',')) {
                throw "Onjuiste CSV-kop in $($file.Name). Verwacht de standaard Autopilot-kolommen, in de juiste volgorde."
            }
            for ($n = 1; $n -lt $lines.Length; $n++) {
                if ([string]::IsNullOrWhiteSpace($lines[$n])) { continue }
                $values = $lines[$n].Split([char]',')
                if ($values.Count -ne $header.Count) { throw "Onjuist aantal velden in $($file.Name), regel $($n + 1)." }
                while ($values.Count -lt 5) { $values += '' }
                Add-ValidatedRow -Values $values -Source "$($file.Name), regel $($n + 1)"
            }
        }
    }
    else {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Open Windows PowerShell als administrator en voer het script opnieuw uit.'
        }
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        if ($osInfo.ProductType -ne 1 -or [version]$osInfo.Version -lt [version]'10.0') {
            throw 'Hardware-export vereist een Windows 10/11-client.'
        }
        $bios = Get-CimInstance -ClassName Win32_BIOS
        try {
            $detail = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' -ClassName MDM_DevDetail_Ext01 `
                -Filter "InstanceID='Ext' AND ParentID='./DevDetail'"
        }
        catch { throw "Hardware-hash kon niet worden gelezen. Controleer administratorrechten en de Windows WMI/MDM-provider. Details: $($_.Exception.Message)" }
        if ($null -eq $detail -or [string]::IsNullOrWhiteSpace([string]$detail.DeviceHardwareData)) {
            throw 'Windows heeft geen Autopilot-hardware-hash teruggegeven. Er wordt geen CSV gemaakt.'
        }
        $values = @(([string]$bios.SerialNumber).Trim(), '', ([string]$detail.DeviceHardwareData).Trim(), $GroupTag.Trim(), $AssignedUser.Trim())
        Add-ValidatedRow -Values $values -Source $env:COMPUTERNAME
        Write-Host "Verzameld: $($env:COMPUTERNAME), serienummer $($values[0])"
    }

    if ($rows.Count -eq 0) { throw 'Geen apparaten verzameld.' }
    if ($rows.Count -gt 500) { throw 'Meer dan 500 apparaten. Verdeel de bronbestanden over kleinere batches.' }
    $parent = [IO.Path]::GetDirectoryName($target)
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $content = New-Object 'System.Collections.Generic.List[string]'
    $content.Add(($columns -join ','))
    foreach ($row in ($rows | Sort-Object Serial)) { $content.Add($row.Line) }
    $tempFile = Join-Path $parent ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($tempFile, (($content -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
        Move-Item -LiteralPath $tempFile -Destination $target -Force:$Force
    }
    finally {
        if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force }
    }
    Write-Host "Gereed: $($rows.Count) apparaat/apparaten. CSV: $target"
    Write-Host 'Importeer in Intune > Devices > Windows > Enrollment > Windows Autopilot > Devices > Import.'
    Write-Output $target
}
catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
