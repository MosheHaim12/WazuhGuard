# Build and validation report — manual diagnostics / 1.1.0

## Scope and verified local results

Four explicit CLI entry points now use the same production primitives as the Windows service. VPN discovery/control shares the RAS, Check Point and FortiClient provider layer. See [MANUAL_VALIDATION.md](MANUAL_VALIDATION.md) for the exact ordered lab sequence and [VPN_SUPPORT.md](VPN_SUPPORT.md) for capabilities and limits.

- Release compilation succeeded with warnings treated as errors.
- Automated tests: **144 passed, 0 failed, 0 skipped** on macOS ARM64 (.NET SDK 10.0.301; test runtime 10.0.9).
- Self-contained **win-x64 publish succeeded**, targeting bundled .NET 10.0.12.
- The original 57 tests remain included; 87 additional cases cover command dispatch, read-only behavior, partial health observations, recovery gating/rechecks, targeted selection/verification, metadata, provider routing/errors, Check Point observation and FortiClient contract safety.
- No actual VPN was enumerated/disconnected locally and no Wazuh installation was changed.

Native Windows CI results will be recorded after the branch build finishes. The workflow runs the full build/test/publish/WiX MSI inspection and a read-only CLI smoke script. Previous 1.0.0 CI produced an MSI but its COM table inspector failed; this change fixes that inspector and reruns it. No Wine validation is used.

## Changed files

- `WazuhGuard/Diagnostics/*`, `Program.cs`, `ProductionServices.cs`: explicit command dispatch, console/output, human-readable results and shared production registrations without starting the worker.
- `WazuhGuard.Core/Contracts.cs`, `GuardOptions.cs`: health diagnostics, provider reports/capabilities, FortiClient opt-in.
- `GuardStateMachine.cs`: skip/log detection-only sessions; grace/recovery/enforcement timing is unchanged.
- `Monitoring/*`: exact service states and partial observations on failures, retaining Unknown safety behavior.
- `Vpn/NativeRasApi.cs`, `RasVpnSessionManager.cs`: additional existing native metadata, unchanged RAS hangup path.
- `Vpn/CompositeVpnSessionManager.cs`, `CheckPointVpnProvider.cs`, `FortiClientVpnProvider.cs`, `VendorCli.cs`, `WindowsVpnEnvironmentProbe.cs`: provider dispatch, bounded documented commands and read-only inventory.
- Tests: new `DiagnosticTests.cs` / `VpnProviderTests.cs`; extended `WindowsProvidersTests.cs` / `GuardStateMachineTests.cs`.
- `scripts/inspect-msi.ps1`, `scripts/smoke-cli.ps1`, `.github/workflows/build.yml`: Windows MSI inspection and real read-only executable smoke checks.
- Version/configuration, README, security/provider/manual/lab/build documentation updated for 1.1.0.

## Acceptance still required

No Check Point or FortiClient compatibility is certified. Check Point is observation-only, FortiClient 7.4.7 targeted control is opt-in and unverified, and RAS still needs real account/profile/protocol acceptance. Windows CI can validate the binary and a missing-service observation, not the connected lab VPN or stopped-Wazuh recovery. Interactive console behavior, LocalSystem vendor visibility, real MSI installation/upgrade lifecycle, signing and full automatic enforcement remain separate acceptance work. No signing identity was supplied; the build is unsigned.
