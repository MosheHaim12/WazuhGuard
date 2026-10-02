[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '1.1.0',
    [ValidateSet('Test', 'Production')][string]$DefaultMode = 'Test',
    [string]$SigningCertificateThumbprint,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'The complete MSI build requires Windows x64 and .NET SDK 10.0.301 or later.' }
if (-not [Environment]::Is64BitProcess) { throw 'Run this script from 64-bit PowerShell.' }
$parts = $Version.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw 'Version exceeds MSI version limits.' }
$root = Split-Path $PSScriptRoot -Parent
$artifacts = Join-Path $root 'artifacts'
$publish = Join-Path $artifacts 'publish'
function Invoke-Checked([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}
Push-Location $root
try {
    New-Item -ItemType Directory -Force $artifacts | Out-Null
    # Only clean this script's generated publish directory, never customer configuration.
    if (Test-Path $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
    Invoke-Checked dotnet @('restore', 'WazuhGuard.sln', '--locked-mode')
    Invoke-Checked dotnet @('build', 'WazuhGuard.sln', '-c', 'Release', '--no-restore', "-p:Version=$Version")
    Invoke-Checked dotnet @('test', 'WazuhGuard.Tests/WazuhGuard.Tests.csproj', '-c', 'Release', '--no-build',
        '--logger', 'trx;LogFileName=WazuhGuard.trx', '--results-directory', "$artifacts/test-results")
    Invoke-Checked dotnet @('publish', 'WazuhGuard/WazuhGuard.csproj', '-c', 'Release', '-r', 'win-x64',
        '--self-contained', 'true', '-p:PublishSingleFile=false', '-p:RestoreLockedMode=true', "-p:Version=$Version", '-o', $publish)
    foreach ($file in @('WazuhGuard.exe', 'coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll', 'System.Diagnostics.EventLog.Messages.dll')) {
        if (-not (Test-Path (Join-Path $publish $file))) { throw "Missing self-contained payload: $file" }
    }
    $configDir = Join-Path $artifacts 'config'
    New-Item -ItemType Directory -Force $configDir | Out-Null
    $configFile = Join-Path $configDir 'appsettings.json'
    $config = Get-Content 'WazuhGuard/appsettings.json' -Raw | ConvertFrom-Json
    $config.WazuhGuard.TestMode = $DefaultMode -eq 'Test'
    [IO.File]::WriteAllText($configFile, ($config | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    if ($SigningCertificateThumbprint) {
        Invoke-Checked signtool @('sign', '/sha1', $SigningCertificateThumbprint, '/fd', 'SHA256', '/tr', $TimestampUrl,
            '/td', 'SHA256', (Join-Path $publish 'WazuhGuard.exe'))
    }
    Invoke-Checked dotnet @('restore', 'WazuhGuard.Setup/WazuhGuard.Setup.wixproj', '--locked-mode')
    Invoke-Checked dotnet @('build', 'WazuhGuard.Setup/WazuhGuard.Setup.wixproj', '-c', 'Release', '--no-restore',
        "-p:Version=$Version", "-p:ConfigFile=$configFile")
    $msi = Join-Path $artifacts 'WazuhGuard-x64.msi'
    if (-not (Test-Path $msi)) { throw 'Installer build did not produce WazuhGuard-x64.msi.' }
    if ($SigningCertificateThumbprint) {
        Invoke-Checked signtool @('sign', '/sha1', $SigningCertificateThumbprint, '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', $msi)
        Invoke-Checked signtool @('verify', '/pa', $msi)
    }
    & (Join-Path $PSScriptRoot 'inspect-msi.ps1') -Path $msi
    (Get-FileHash $msi -Algorithm SHA256).Hash + '  WazuhGuard-x64.msi' | Set-Content "$msi.sha256"

    # The installed service remains a WinExe so it never opens a console window.
    # Re-publish only the manual diagnostic artifact as a Console executable.
    # PowerShell/cmd then wait for it to finish and display output in natural order.
    Invoke-Checked dotnet @('publish', 'WazuhGuard/WazuhGuard.csproj', '-c', 'Release', '-r', 'win-x64',
        '--self-contained', 'true', '-p:PublishSingleFile=false', '-p:RestoreLockedMode=true',
        '-p:OutputType=Exe', "-p:Version=$Version", '-o', $publish)
    Write-Host "Manual diagnostic publish rebuilt as Console executable: $publish"
    Write-Host "Installer built and inspected: $msi (new installation mode: $DefaultMode)"
}
finally { Pop-Location }
