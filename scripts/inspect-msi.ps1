[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase((Resolve-Path $Path).Path, 0)
function Rows([string]$Sql) {
    $view = $db.OpenView($Sql)
    try {
        $view.Execute()
        while ($record = $view.Fetch()) {
            $row = @()
            for ($i = 1; $i -le $record.FieldCount; $i++) { $row += $record.StringData($i) }
            ,$row
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($record)
        }
    }
    finally { $view.Close(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view) }
}
try {
    $services = @(Rows 'SELECT `Name`, `StartType`, `StartName` FROM `ServiceInstall`')
    if ($services.Count -ne 1 -or $services[0][0] -ne 'WazuhGuard' -or $services[0][1] -ne '2' -or $services[0][2] -ne 'LocalSystem') {
        throw 'MSI does not install the expected automatic LocalSystem service.'
    }
    $controls = @(Rows 'SELECT `Name`, `Event`, `Wait` FROM `ServiceControl`')
    if ($controls.Count -ne 1 -or $controls[0][0] -ne 'WazuhGuard' -or $controls[0][2] -ne '1') { throw 'Service lifecycle controls missing.' }
    $controlFlags = [int]$controls[0][1]
    if (($controlFlags -band 163) -ne 163) { throw 'Install-start / stop-both / uninstall-delete flags missing.' }
    $recovery = @(Rows 'SELECT `FirstFailureActionType`, `SecondFailureActionType`, `ThirdFailureActionType`, `RestartServiceDelayInSeconds` FROM `Wix4ServiceConfig`')
    if ($recovery.Count -ne 1 -or $recovery[0][0] -ne 'restart' -or $recovery[0][1] -ne 'restart' -or $recovery[0][2] -ne 'restart' -or $recovery[0][3] -ne '30') {
        throw 'Service recovery policy is missing or incorrect.'
    }
    $files = @(Rows 'SELECT `FileName` FROM `File`') | ForEach-Object { $_[0] }
    foreach ($required in @('WazuhGuard.exe', 'coreclr.dll', 'hostfxr.dll', 'appsettings.json')) {
        if (-not ($files | Where-Object { ($_ -split '\|')[-1] -eq $required })) { throw "MSI payload missing $required" }
    }
    if (@(Rows 'SELECT `SddlText` FROM `MsiLockPermissionsEx`').Count -lt 3) { throw 'ProgramData ACLs missing.' }
    if (@(Rows 'SELECT `UpgradeCode` FROM `Upgrade`').Count -lt 2) { throw 'Upgrade/downgrade rules missing.' }
    if (@(Rows 'SELECT `Condition` FROM `LaunchCondition`').Count -lt 2) { throw 'OS/elevation requirements missing.' }
    Write-Host "MSI inspection passed: $($files.Count) files, service lifecycle, recovery, ACLs, upgrade and platform rules."
}
finally {
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
}
