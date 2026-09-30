# WazuhGuard

WazuhGuard is an independent, silent LocalSystem Windows service that monitors the local Wazuh Agent. After a verified outage, bounded recovery attempts and a grace period, it disconnects active Windows RAS VPN sessions. It keeps checking for reconnections and stops interfering as soon as Wazuh is healthy.

**New installations default to TestMode.** Monitoring, Wazuh recovery, grace periods and VPN discovery are active, but VPN hangup is suppressed. A production-default installer can be built with `-DefaultMode Production`; an existing installation's configuration always takes precedence on upgrade.

See `BUILD_REPORT.md` for checks actually executed on this deliverable. A successful build is not a substitute for the Windows acceptance sequence in `LAB_TESTING.md`.

## Customer installation

Supported target: Windows 11 x64 and Windows Server 2022/2025 x64, on a Microsoft-supported servicing release. Windows ARM64 and x86 are rejected. Install the Wazuh Agent independently; WazuhGuard never installs or recreates Wazuh.

Double-click `artifacts/WazuhGuard-x64.msi`, approve elevation, and finish the Windows Installer operation. The MSI contains the .NET 10.0.12 runtime and all application dependencies. Customers need no runtime, SDK, Visual Studio, PowerShell installation script, or service-registration command. The installed application has no console window, tray icon, notification or other UI.

The MSI installs `C:\Program Files\WazuhGuard`, creates protected configuration/log directories, registers `WazuhGuard` / **Wazuh Guard** as automatic LocalSystem, configures first/second/subsequent crash recovery to restart after 30 seconds, validates configuration and starts the service. MSI start failures fail the installation. There is no Wazuh service dependency: WazuhGuard must also start when Wazuh is absent.

Enterprise deployment, from an elevated deployment agent:

```powershell
msiexec.exe /i WazuhGuard-x64.msi /qn /norestart /L*v C:\Windows\Temp\WazuhGuard-install.log
```

Exit 0 means success; 3010 means success with reboot required; other codes are failures. Uninstall through Settings → Apps, or `msiexec.exe /x WazuhGuard-x64.msi /qn /norestart`. Uninstall stops/deletes WazuhGuard and removes its executable/runtime/event source. Configuration and logs are intentionally retained for audit, upgrade and reinstall. After uninstall, an administrator may remove `%ProgramData%\WazuhGuard` if retention is no longer needed. Uninstall does not affect Wazuh or VPN profiles.

## Configuration and operation

Both modes use **`C:\ProgramData\WazuhGuard\appsettings.json`** (or `%ProgramData%` on a nonstandard installation). The MSI restricts the directory, configuration and logs to SYSTEM and Administrators. Configuration is loaded once at startup, without current-directory, environment-variable or command-line overrides. After an administrator edits it, restart the WazuhGuard service through Services. Unknown/duplicate JSON keys, invalid types and invalid values fail startup; they never silently enable enforcement.

| Setting | Default | Allowed values |
| --- | --- | --- |
| WazuhServiceName | WazuhSvc | Valid service name, excluding WazuhGuard |
| WazuhInstallPath | C:\Program Files (x86)\ossec-agent | Absolute local directory, no traversal/wildcards |
| CheckIntervalSeconds | 10 | 1–300 |
| GracePeriodSeconds | 120 | 1–86400 |
| RestartAttempts | 3 | 0–10; 0 disables recovery |
| RestartTimeoutSeconds | 15 | 1–120, per attempt |
| RestartDelaySeconds | 5 | 1–300, between attempts |
| VpnDisconnectTimeoutSeconds | 10 | 1–60 |
| TestMode | true | Boolean; false enables hangup |

Example configuration is in `WazuhGuard/appsettings.json`. All timing units are seconds. A service that is stopped is started; the provider never kills or forcibly stops Wazuh. A service pending a transition is observed during grace. A paused service enters grace rather than receiving an unrequested Continue operation. Missing service or installation bypasses recovery and enters grace directly.

Recovery is attempted once per verified outage, with configured spacing and timeout. The full grace period starts after recovery fails. Maximum normal initial latency includes the polling interval, recovery attempts/delays, grace period and a final poll. Once enforcing, reconnections are detected on later polling cycles; there can be a short connected window. The application does not promise instantaneous VPN denial.

Any monitoring exception becomes **unknown**, suspends enforcement, and invalidates the old deadline. A subsequent verified unhealthy observation starts a fresh full grace period. Wazuh must still be verified unhealthy immediately before each disconnect. An unavoidable race remains between a health observation and the native hangup call; Windows provides no atomic transaction spanning both services and RAS.

State is deliberately not persisted across restarts: each WazuhGuard restart/reboot requires fresh observations and grace. An administrator repeatedly restarting WazuhGuard can therefore defer enforcement. This is consistent with the documented administrator security boundary.

## Logs

Structured JSON Lines: `%ProgramData%\WazuhGuard\logs\wazuhguard-*.jsonl`. Each event includes time, level, message template, rendered message, structured properties and exception information where applicable. Files roll daily or at 10 MiB, retaining the most recent 31 files (approximately 310 MiB maximum, plus a final event). Unbuffered writes make recent events available while the service runs. Startup/host failures and file-sink failures also attempt to write to Application Event Log, source `WazuhGuard`.

Startup prominently identifies TEST or PRODUCTION mode and version. Health/state changes, recovery attempts, grace entry/expiry, VPN discovery changes, disconnect attempts/results and shutdown are logged. Identical health observations and unchanged empty VPN sets are quiet. TestMode logs `TEST MODE: Would disconnect VPN session: ...` once per observed session identity per outage. API error traces are rate-limited to five minutes per operation; retry continues each tick. Production disconnect attempts remain visible. Names/connection identifiers may be sensitive operational data; no credentials are read or logged.

## Architecture

* `WazuhGuard.Core`: immutable options, interfaces and explicit Healthy → Recovering → GracePeriod → Enforcing state machine. `TimeProvider` supplies monotonic grace deadlines; a semaphore serializes ticks.
* `WazuhGuard`: Worker Service host, strict ProgramData configuration, rotating logs, `ServiceController` health/recovery, native RAS interop and session provider. `Worker.cs` only schedules and manages lifecycle.
* `WazuhGuard.Tests`: fake-only unit/state-machine/provider tests. No tests instantiate the native RAS implementation or operate a real service/VPN.
* `WazuhGuard.Setup`: WiX 6.0.2 MSI authoring, service tables, recovery extension, restrictive ACLs, config validation and major upgrades.
* `scripts/build.ps1`: restore, Release build, tests, self-contained win-x64 publish, MSI build and MSI table inspection; optional Authenticode signing.

`IWazuhHealthMonitor`, `IWazuhRecoveryService`, `IVpnSessionManager` and `IGuardStateMachine` separate policy from Windows operations. New VPN providers implement `IVpnSessionManager`; a composite may dispatch using `VpnSession.Provider` without changing the state machine. Future maintenance/upgrade detection can decorate the health monitor to return Unknown while authorized maintenance is active, which suspends enforcement and requires a fresh grace afterward. No installer-process heuristic is implemented.

## Repeatable Windows build

Build prerequisites (developer/CI only): Windows x64, .NET SDK 10.0.301 or newer stable .NET 10 SDK, Windows PowerShell 5.1 or PowerShell 7, and NuGet access. WiX is restored by its pinned SDK project; Visual Studio is unnecessary. WiX's distribution terms include its [Open Source Maintenance Fee](https://docs.firegiant.com/wix/osmf/); the build tooling terms are separate from customer runtime prerequisites.

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

For a fresh-install production default and a new version:

```powershell
.\scripts\build.ps1 -Version 1.0.1 -DefaultMode Production
```

The first three version fields are MSI-significant; increment one for every release. Keep the UpgradeCode and component GUIDs stable. Same-version installation is maintenance, not an upgrade. Downgrades are blocked. The early major-upgrade removal is inside the MSI transaction, permitting rollback. Mutable config is Permanent/NeverOverwrite: edited settings survive upgrades and repairs.

Outputs: `artifacts/WazuhGuard-x64.msi`, `.msi.sha256`, self-contained payload in `artifacts/publish`, selected initial config in `artifacts/config`, and TRX test evidence in `artifacts/test-results`. Locked package references and committed lock files detect dependency drift. The GitHub Actions workflow runs the same command on Windows.

The application is intentionally published as a **self-contained directory inside one compressed MSI**. This installs the runtime directly in protected Program Files and avoids extracting bundled native DLLs into LocalSystem's temporary directory. The customer still receives exactly one installer. This is more predictable for servicing and event-message resources than a self-extracting single-file service.

Optional signing requires your organization's code-signing certificate already installed and Windows SDK `signtool` available:

```powershell
.\scripts\build.ps1 -SigningCertificateThumbprint $env:WAZUHGUARD_SIGNING_THUMBPRINT
```

Without that argument the MSI is unsigned; no signing identity is fabricated. Sign and timestamp an approved release before customer distribution where organizational policy requires it. The script signs the application before MSI packaging, then signs and verifies the MSI.

For fake-only tests on macOS/Linux with .NET 10, run `dotnet restore WazuhGuard.sln` then `dotnet test WazuhGuard.Tests -c Release`. These exercise managed logic and ABI layouts, not native Windows APIs. Native WiX MSI creation/validation requires Windows; see the build report for any compatibility-layer build used for this delivery.

## Boundaries

Read `VPN_SUPPORT.md` for the precise RAS scope and `SECURITY.md` for trust boundaries. WazuhGuard does not modify firewall rules, adapters, routes, DNS, credentials or profiles, does not kill VPN processes, and does not prevent reconnection. It does not verify Wazuh manager connectivity, event delivery, agent integrity or the authenticity of the service executable. It is not tamper-proof against Local Administrator or SYSTEM.
