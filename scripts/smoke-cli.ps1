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
