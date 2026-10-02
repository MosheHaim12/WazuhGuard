> For the current manual-primitives task, use [MANUAL_VALIDATION.md](MANUAL_VALIDATION.md) first. The full automatic scenarios below are a separate later acceptance stage and were not executed for this change.

# Disposable Windows VM acceptance test

Run this entire sequence on a disposable Windows 11 x64 or Server 2022/2025 x64 VM with a hypervisor console, snapshot and a lab VPN endpoint. Use a local administrator. Do not use a production endpoint, an administrator's workstation or a remote-access-only VM. Record OS build, Wazuh version, VPN protocol/profile scope, installer SHA256 and test timestamps.

**DISCONNECTION TEST** marks any action that can intentionally disconnect the VM's VPN. Maintain hypervisor-console access throughout those steps. WazuhGuard does not block the underlying LAN, but the remote session may depend on the VPN. Never run the production phase in an automated development-machine test suite.

The commands below are acceptance-test operations by the lab administrator. The customer installer itself performs service registration/start/recovery configuration without these commands. PowerShell examples assume an elevated PowerShell console. Run the TestMode phase first; confirm the configuration before stopping Wazuh.

## Prepare and install

1. Snapshot the clean VM. Install and enroll the Wazuh Windows agent using the [official Windows installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html), connecting it to your lab manager. Use the current signed agent package from Wazuh. This acceptance test does not prescribe or embed deployment credentials.
2. Verify the default service and directory:

   ```powershell
   Get-Service WazuhSvc
   Test-Path 'C:\Program Files (x86)\ossec-agent'
   ```

   Expected: Running and True. Also check the agent's registration/health in the lab manager independently. WazuhGuard's service/directory checks do not prove manager connectivity.
3. Copy `WazuhGuard-x64.msi` and its SHA256 file into `C:\Lab`. Verify `Get-FileHash C:\Lab\WazuhGuard-x64.msi -Algorithm SHA256`. Double-click the MSI, approve UAC and complete installation. No .NET installation or developer tools should be required on this VM. For repeatable deployment testing:

   ```powershell
   $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i C:\Lab\WazuhGuard-x64.msi /qn /norestart /L*v C:\Lab\install.log'
   $p.ExitCode
   ```

   Expect 0 (or 3010 with the required reboot). Any other code fails this step; retain the MSI log.
4. Verify service configuration and Running status:

   ```powershell
   Get-CimInstance Win32_Service -Filter "Name='WazuhGuard'" |
       Select-Object Name, DisplayName, State, StartMode, StartName, PathName
   ```

   Expect WazuhGuard, Wazuh Guard, Running, Auto, LocalSystem and the Program Files executable. In Services → Wazuh Guard → Recovery, verify Restart the Service for first, second and subsequent failures with a 30-second delay.
5. Verify Wazuh remains Running for at least three monitoring intervals. Inspect logs from an elevated console:

   ```powershell
   $cfg = 'C:\ProgramData\WazuhGuard\appsettings.json'
   function Read-GuardLog {
       Get-ChildItem 'C:\ProgramData\WazuhGuard\logs\*.jsonl' |
           Sort-Object LastWriteTime |
           ForEach-Object { Get-Content $_.FullName } |
           ForEach-Object { $_ | ConvertFrom-Json } |
           Select-Object Timestamp, Level, RenderedMessage
   }
   Read-GuardLog
   ```

   Expect startup/version, configuration validation, **TEST MODE** and healthy Wazuh. Confirm no recurring disconnect attempts. Check from a standard-user account that the config/log directories cannot be modified. Confirm no app console, tray icon, toast or popup.
6. Create a test connection using Windows Settings → Network & internet → VPN → Add VPN → provider **Windows (built-in)**. Enter your lab endpoint and authorized lab credentials, selecting IKEv2 or SSTP to match the lab server. Connect. Confirm the VPN works using the lab's connectivity check. Do not rely solely on a third-party client that RAS cannot see.

## TestMode flow

7. Ensure TestMode explicitly:

   ```powershell
   $settings = Get-Content $cfg -Raw | ConvertFrom-Json
   $settings.WazuhGuard.TestMode = $true
   [IO.File]::WriteAllText($cfg, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
   Restart-Service WazuhGuard
   Read-GuardLog
   ```

   Confirm a new TEST MODE startup record. Retain default timings for the first full acceptance run.
8. With the test VPN connected, stop Wazuh once:

   ```powershell
   Stop-Service WazuhSvc
   ```

9. Wait at least 30 seconds and inspect services/logs. Expect stopped detection, Healthy → Recovering, a start attempt, Running, and Recovering → Healthy. VPN should remain connected. If Wazuh's own service recovery wins the race, repeat once and use timestamps to establish which recovery occurred; do not assume the WazuhGuard path was exercised.
10. Simulate unrecoverable Wazuh without deleting its files or service:

    ```powershell
    Set-Service WazuhSvc -StartupType Disabled
    Stop-Service WazuhSvc
    ```

    Confirm it stays Stopped. WazuhGuard should log failed start attempts and enter GracePeriod. **TestMode still attempts Wazuh recovery**; it only suppresses VPN disconnect.
11. Wait for all configured attempts/delays plus 120 seconds grace and another polling interval (allow up to four minutes). Verify no early enforcement and a final health check at grace expiry.
12. Inspect the guard's own logs, produced by LocalSystem. Expect Enforcing and discovery of the active VPN with connection name/ID/device description. An interactive `Get-VpnConnection` result is not proof that the service can see it. If the service cannot detect the test tunnel, this OS/profile/protocol combination fails support qualification.
13. Expect `TEST MODE: Would disconnect VPN session: ...`. Confirm Windows still shows connected and the VPN traffic check still succeeds. Leave connected across several ticks; unchanged test notifications should not flood the log.
14. Restore Wazuh:

    ```powershell
    Set-Service WazuhSvc -StartupType Automatic
    Start-Service WazuhSvc
    ```

15. Within the next interval, confirm Enforcing → Healthy, no additional would-disconnect records, and a working VPN. Save this phase's logs and snapshot.

## Production flow — DISCONNECTION TESTS

16. **DISCONNECTION TEST: enable production only on this disposable VM.** Keep the hypervisor console open, verify Wazuh is Running, then set the same configuration's TestMode to false and restart the guard:

    ```powershell
    $settings = Get-Content $cfg -Raw | ConvertFrom-Json
    $settings.WazuhGuard.TestMode = $false
    [IO.File]::WriteAllText($cfg, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Restart-Service WazuhGuard
    Read-GuardLog
    ```

    Confirm **PRODUCTION MODE**. While Wazuh remains healthy, confirm the connected VPN is left alone.
17. **DISCONNECTION TEST:** repeat step 10's disabled/stopped Wazuh condition. Wait through recovery/grace. Confirm no premature hangup.
18. **DISCONNECTION TEST:** confirm the guard logs a disconnect attempt and `Disconnected` result, Windows VPN reports disconnected, and the lab VPN session/traffic ends. Preserve both endpoint logs and available VPN server evidence. Merely seeing “attempt” is not a pass.
19. **DISCONNECTION TEST:** while Wazuh remains disabled/stopped, reconnect the same VPN from Windows Settings.
20. **DISCONNECTION TEST:** confirm it disconnects again within a normal check interval plus API cleanup time. Record the new connection identity. Repeat with two simultaneous eligible VPN connections if the lab supports them; confirm both are handled independently.
21. Restore Wazuh to Automatic and Running as in step 14.
22. Reconnect the VPN once the guard logs Healthy.
23. Verify WazuhGuard leaves the VPN connected across at least three intervals. There must be no changed firewall rules, routes, DNS configuration, disabled adapters, deleted profiles/credentials or automatic VPN establishment by WazuhGuard. Normal VPN connect/disconnect may itself update routes/DNS; distinguish Windows VPN behavior from guard activity.
24. Reboot the VM with Wazuh restored. A reboot itself interrupts the VPN; this is not evidence of guard enforcement.
25. Verify both services return Running automatically, the guard mode/version log appears, and a reconnected VPN remains connected. Also test one **DISCONNECTION TEST** reboot with Wazuh deliberately disabled: guard startup must allow fresh grace before enforcing. Restore Wazuh immediately afterward.

## Uninstall and upgrade

26. Restore TestMode=true, ensure Wazuh is Running, then uninstall WazuhGuard using Settings → Apps or:

    ```powershell
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/x C:\Lab\WazuhGuard-x64.msi /qn /norestart /L*v C:\Lab\uninstall.log'
    $p.ExitCode
    Get-Service WazuhGuard -ErrorAction SilentlyContinue
    Test-Path 'C:\Program Files\WazuhGuard\WazuhGuard.exe'
    ```

    Expect success, no guard service, no guard executable, and Wazuh unaffected. The existing VPN must not be disconnected by uninstall. ProgramData config/logs remain by design. Reinstallation must preserve that retained TestMode/config. For a pristine-install test, snapshot then remove only `C:\ProgramData\WazuhGuard` after uninstall.
27. On the build machine, preserve the 1.0.0 MSI, then build `scripts/build.ps1 -Version 1.0.1`. On the VM install 1.0.0 in TestMode, set GracePeriodSeconds to 150 and record the config hash. Install 1.0.1 without first uninstalling. Expect one installed product, one Running automatic LocalSystem service, new version logged and an unchanged config hash. Verify recovery policy and ACLs again. Attempt to install 1.0.0 over 1.0.1: expect a clear downgrade failure and 1.0.1 still Running. Exercise MSI repair and then uninstall 1.0.1. Record any reboot request and test rollback from an induced installation failure on a snapshot (for example, pre-existing invalid retained configuration).

## Additional release gates

* With TestMode=true, stop the guard, set WazuhServiceName to `WazuhGuard-Lab-Nonexistent`, restart it, and verify missing-service → GracePeriod → would-disconnect. Restore the original configuration; no Wazuh service is deleted.
* Repeat with WazuhInstallPath pointing to `C:\WazuhGuard-Lab-Nonexistent`; verify installation-missing behavior despite a Running Wazuh service. Restore configuration.
* Introduce an invalid JSON value or misspelled property while the guard is stopped. Startup must fail with a log/event and no VPN activity. Restore the saved file. Repeat MSI installation against invalid retained configuration and verify nonzero install result/rollback.
* Simulate an update interruption shorter than grace and restore Wazuh; there must be no hangup. Do not whitelist arbitrary `msiexec` processes.
* On a snapshot, terminate the **WazuhGuard service process only** using Task Manager Details. Verify SCM restarts it after approximately 30 seconds. Do not kill a VPN client process. Repeat enough times to verify subsequent-failure recovery, then confirm clean service stop does not trigger a restart.
* Repeat LocalSystem discovery/hangup acceptance for each supported protocol/profile scope: user-only and all-user; multiple logged-in users; Always On device/user tunnel if used. Mark all production cases **DISCONNECTION TEST** and retain the matrix. Unseen or non-disconnectable tunnels must be documented as unsupported in that deployment.
* Confirm installer rejection on x86/ARM64 and unsupported OS versions using dedicated VMs, without bypassing launch conditions.
* Confirm no SDK/runtime prerequisite on a clean Windows VM. If organizational policy requires signatures, verify the signed MSI and EXE publisher before installation.

Acceptance is complete only after recording observed results, expected results, logs and remaining exceptions. Do not mark these manual checks passed based on unit tests, MSI table inspection or a compatibility-layer build.
