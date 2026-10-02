[CmdletBinding()]
param([string]$Executable = (Join-Path $PSScriptRoot '..\artifacts\publish\WazuhGuard.exe'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'This read-only native smoke check requires Windows.' }
$Executable = (Resolve-Path $Executable).Path
function Invoke-Diagnostic([string[]]$CommandArguments, [int]$ExpectedExit, [string]$ExpectedText) {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $CommandArguments) { [void]$start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Diagnostic process did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Read-only diagnostic timed out.' }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        Write-Host $output
        if ($process.ExitCode -ne $ExpectedExit -or -not $output.Contains($ExpectedText)) {
            throw "Unexpected diagnostic result: exit=$($process.ExitCode), expected=$ExpectedExit / $ExpectedText"
        }
    }
    finally { $process.Dispose() }
}
# First prove the published artifact is a real Windows Console-subsystem executable.
# A redirected ProcessStartInfo check alone would also pass for a WinExe and would not catch
# the PowerShell symptom where the prompt returns before output is displayed.
$peBytes = [IO.File]::ReadAllBytes($Executable)
$peOffset = [BitConverter]::ToInt32($peBytes, 0x3c)
$optionalHeader = $peOffset + 24
$magic = [BitConverter]::ToUInt16($peBytes, $optionalHeader)
if ($magic -ne 0x10b -and $magic -ne 0x20b) { throw ("Unexpected PE optional-header magic: 0x{0:X}" -f $magic) }
# IMAGE_OPTIONAL_HEADER.Subsystem is at offset 0x44 from the start of both
# PE32 and PE32+ optional headers. (The previous check incorrectly used 0x5c
# for PE32+, which reads a different field and falsely reported subsystem=0.)
$subsystemOffset = $optionalHeader + 0x44
$subsystem = [BitConverter]::ToUInt16($peBytes, $subsystemOffset)
if ($subsystem -ne 3) { throw "Manual artifact is not Windows CUI/Console subsystem (subsystem=$subsystem)." }
Write-Host 'PE subsystem PASS: manual artifact is Windows Console (CUI).'
Invoke-Diagnostic @('--help') 0 'WazuhGuard manual diagnostics'
Invoke-Diagnostic @('--invalid-command') 2 'Unknown command'
# Dedicated CI runner only: never overwrite an installed endpoint's configuration.
$data = Join-Path $env:ProgramData 'WazuhGuard'
if (Test-Path $data) { throw 'Existing ProgramData configuration found. Refusing to overwrite it for the smoke check.' }
New-Item -ItemType Directory $data | Out-Null
try {
    $configPath = Join-Path $data 'appsettings.json'
    $config = @{ WazuhGuard = @{ WazuhServiceName = "WazuhGuardSmokeMissing_$([Guid]::NewGuid().ToString('N'))"; WazuhInstallPath = $env:SystemRoot; TestMode = $true } }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10))
    $before = (Get-FileHash $configPath).Hash
    Invoke-Diagnostic @('--check-wazuh') 1 'Overall health: Unhealthy (ServiceMissing)'
    if ((Get-FileHash $configPath).Hash -ne $before) { throw 'Read-only command changed configuration.' }
    if (Test-Path (Join-Path $data 'logs')) { throw 'CLI unexpectedly initialized the service file logger.' }
}
finally { Remove-Item -LiteralPath $data -Recurse -Force }
Write-Host 'CLI smoke PASS: redirected WinExe output/exit codes, dispatch, and a real read-only missing-service observation. No VPN APIs or recovery commands invoked.'
