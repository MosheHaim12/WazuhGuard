# Manual primitive validation — Windows x64

These commands invoke the same production health, recovery, discovery and disconnect components as the service. They do not start the worker/state machine. No Wazuh uninstall, installation deletion or full automatic enforcement scenario belongs to this procedure.

## Prepare once

Use an elevated **64-bit PowerShell** on the lab endpoint, with an existing Wazuh Agent and the VPN connected. Extract the entire published `publish` directory to `C:\Lab\WazuhGuard` (all runtime files are required). No .NET installation is needed. Alternatively use the installed 1.1.0 application at `C:\Program Files\WazuhGuard\WazuhGuard.exe` and change `$exe` below. Do not run a previous 1.0.0 executable.

Stop the **WazuhGuard** automatic service, if installed, to isolate the primitives. Leave **WazuhSvc** running until step e. An old guard would otherwise recover Wazuh or enforce concurrently with the manual test.

```powershell
$exe = 'C:\Lab\WazuhGuard\WazuhGuard.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Extract the complete published application first.' }
$guard = Get-Service -Name WazuhGuard -ErrorAction SilentlyContinue
if ($guard) {
    Stop-Service -Name WazuhGuard -ErrorAction Stop
    (Get-Service WazuhGuard).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90))
}
$configPath = Join-Path $env:ProgramData 'WazuhGuard\appsettings.json'
```

The CLI reads only this ProgramData configuration, exactly like the service. An MSI installation supplies it. For a fresh **portable lab** without existing configuration, copy the supplied `appsettings.example.json` (also available as `WazuhGuard/appsettings.json` in source) using the following block; it refuses to overwrite an existing file. Set `$sample` to its actual extracted location.

```powershell
$sample = 'C:\Lab\appsettings.example.json'
if (-not (Test-Path -LiteralPath $configPath)) {
    if (-not (Test-Path -LiteralPath $sample)) { throw 'Set $sample to the supplied configuration example.' }
    $data = Split-Path $configPath
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $data -AclObject $acl
    Copy-Item -LiteralPath $sample -Destination $configPath -ErrorAction Stop
}
Get-Content -LiteralPath $configPath
```

Check `WazuhServiceName` (normally `WazuhSvc`) and `WazuhInstallPath` (normally `C:\Program Files (x86)\ossec-agent`) against the actual installation. Keep TestMode true for observation. Existing configurations need no new key: `EnableFortiClientDisconnect` defaults to false when omitted.

The binary is intentionally a Windows **WinExe**. PowerShell can return immediately from direct invocation; use `Start-Process -NoNewWindow -Wait -PassThru` below. Each command prints its account, configuration path and detailed findings. `$p.ExitCode` is reliable; do not rely on a stale `$LASTEXITCODE`. Commands run as your current account, not as LocalSystem.

## First command on the Check Point-connected machine

After the preparation above, run:

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--list-vpn' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

Paste the complete output back. Check Point should yield read-only `trac info` evidence if its recognized installed utility is available; matching services/adapters may also appear. Whether your active tunnel appears in RAS is not yet known. **A zero supported-session count does not mean Check Point is disconnected.** This build has no Check Point-specific disconnect implementation. If no selectable supported session is exposed, step c is blocked for that client; do not disable adapters or stop vendor services to substitute for it. See [VPN_SUPPORT.md](VPN_SUPPORT.md).

## Ordered validation a–h

Run each step separately and inspect its output before continuing. Do not paste the entire sequence as an unattended script.

### a. Check running Wazuh

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--check-wazuh' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

Expected: service exists Yes, Windows state Running, installation exists/accessibility Yes, Overall health Healthy, exit 0. No repair occurs.

### b. List the currently connected VPN

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--list-vpn' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

Record provider result/capabilities, session ID/name/state/device/endpoints and vendor evidence. Unavailable metadata is explicit. Provider Error yields exit 3 with other providers' evidence retained. ObservationOnly/Unsupported can yield exit 0: this means the query completed, not that the tunnel is controllable. If several sessions exist, select the intended full ID; do not guess by adapter name.

### c. Disconnect one supported VPN through WazuhGuard

Only proceed if step b shows a selectable session with disconnect supported/enabled true. TestMode deliberately blocks disconnect, so first back up configuration and enable actual lab hangup while the automatic guard remains stopped:

```powershell
$backup = "$configPath.manual-backup-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff'))"
Copy-Item -LiteralPath $configPath -Destination $backup -ErrorAction Stop
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$config.WazuhGuard.TestMode = $false
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
```

For **exactly one** supported session:

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--disconnect-vpn' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

For multiple sessions, use the complete current `ras:...` or `forti-profile:...` session ID from the listing (these IDs contain no spaces):

```powershell
$sessionId = 'PASTE-THE-EXACT-SESSION-ID-FROM-LIST-VPN'
$p = Start-Process -FilePath $exe -ArgumentList @('--disconnect-vpn', $sessionId) -NoNewWindow -Wait -PassThru
$p.ExitCode
```

The selected session is printed before the changing operation. Afterward the shared discovery layer runs again. Expected: PASS, selected session absent, exit 0. Still-active target yields FAIL/exit 5; API/verification uncertainty yields exit 3. No session/multiple matches/missing identifier yields exit 2. TestMode or a detection-only session yields exit 4. A different same-profile RAS session is reported as possible reconnection and is not disconnected again by this command.

**Check Point:** raw observation alone cannot authorize step c; there is no generic fallback. If it is independently exposed as a supported RAS session, the existing RAS primitive can be tested against that ID, but do not claim Check Point compatibility before observing the actual result.

**FortiClient:** targeted control is a separate, unverified lab opt-in for the 7.4.7 contract. To undertake that acceptance, explicitly add/set the following on `$config` and write it back as above before invoking the command:

```powershell
$config.WazuhGuard | Add-Member -NotePropertyName EnableFortiClientDisconnect -NotePropertyValue $true -Force
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
```

Both TestMode=false and this flag are required. The command always targets one tunnel name. Unsupported versions/output are refused.

### d. Reconnect the VPN

Reconnect the same profile using its normal VPN client UI. Then observe it again:

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--list-vpn' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

Confirm the client UI and diagnostic evidence agree. WazuhGuard never creates a VPN connection. If c was blocked, report it as blocked, not passed, and keep the existing VPN connected for the remaining independent health checks.

### e. Stop WazuhSvc manually

With automatic WazuhGuard still stopped, stop only the configured Wazuh service. If your configured service name differs, use that name here.

```powershell
Stop-Service -Name WazuhSvc -ErrorAction Stop
(Get-Service WazuhSvc).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
Get-Service WazuhSvc
```

No files are deleted and nothing is uninstalled. Ensure no other recovery mechanism immediately starts the service; record that behavior if it happens.

### f. Read-only stopped health check

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--check-wazuh' -NoNewWindow -Wait -PassThru
$p.ExitCode
Get-Service WazuhSvc
```

Expected: Unhealthy (Stopped), installation present, exit 1, service remains Stopped. The command does not repair it.

### g. Check and repair

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--check-and-repair-wazuh' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

Expected: initial Stopped, production recovery attempt with configured retries/timeouts, post-recovery Healthy, PASS/exit 0. `RestartAttempts=0` disables recovery. Healthy means no action; Unknown, missing service or missing installation never triggers reinstall or a guessed restart. Errors and unsuccessful post-checks return nonzero.

### h. Verify Healthy again

```powershell
$p = Start-Process -FilePath $exe -ArgumentList '--check-wazuh' -NoNewWindow -Wait -PassThru
$p.ExitCode
Get-Service WazuhSvc
```

Expected: Healthy/Running, exit 0. Restore the backed-up configuration if step c changed it:

```powershell
if ($backup -and (Test-Path -LiteralPath $backup)) {
    Copy-Item -LiteralPath $backup -Destination $configPath -Force -ErrorAction Stop
}
```

Leave the automatic guard stopped at this stage; starting the full enforcement scenario is a separate acceptance task. If Wazuh recovery failed, restore the lab's Wazuh service using its normal administration procedure and retain the error output.

## Evidence and interpretation

To capture any invocation, add distinct `-RedirectStandardOutput C:\Lab\vpn-output.txt -RedirectStandardError C:\Lab\vpn-error.txt` paths to `Start-Process`, then paste both files and `$p.ExitCode`. Use different filenames per step. Output may contain internal gateway/site/account information; redact secrets before sharing while preserving state/format and consistent identifiers. Do not include VPN credentials.

Exit codes: 0 healthy/PASS/query completed; 1 verified unhealthy; 2 usage/selection; 3 Unknown/API/configuration error; 4 disconnect blocked/unsupported; 5 target still active after disconnect; 130 cancelled. Ctrl+C prevents additional work but cannot undo a hangup already issued.

Record Windows version, Wazuh version, VPN product/version, interactive account, configuration (without secrets), client UI state before/after and full CLI output. This sequence does not validate LocalSystem visibility, MSI install/upgrade/recovery, manager connectivity, packet isolation, every vendor edition, or the full state machine against real infrastructure. Unit tests and Windows smoke tests do not establish those claims.
