# Build and validation report — 2026-09-30

## Ready for Windows handoff

Implemented C# source, fake-only automated tests, a published self-contained Windows x64 application, WiX installer authoring, the Windows build/inspection scripts, CI workflow and full lab documentation are included.

**No MSI was produced.** The user requested stopping the macOS/Wine attempt and completing installer work on Windows. Do not describe this handoff as a validated customer-ready installer.

## Executed results

| Check | Result |
| --- | --- |
| NuGet dependency restore | Passed |
| .NET Release application build | Passed; 0 warnings, 0 errors |
| Automated tests | 57 passed, 0 failed, 0 skipped |
| Self-contained win-x64 publish | Passed |
| Published host inspection | PE32+ GUI executable, x86-64 |
| Bundled runtime manifest | Microsoft.NETCore.App 10.0.12 included |
| WiX SDK/extension restore | Passed, 6.0.2 |
| Native macOS MSI build | Failed: WiX supports Windows only |
| Portable Windows .NET under Wine | Runtime failed; no MSI build completed |
| Native Windows service/MSI/VPN acceptance | Not executed |
| Authenticode signing | Not executed; no signing identity supplied |

Build host: macOS ARM64. Installed build SDK: .NET 10.0.301, test host runtime 10.0.9. Target application: .NET 10 LTS with pinned 10.0.12 packages/runtime. A sandboxed shared-compiler build stalled; the successful build/test/publish commands ran outside that sandbox. No actual VPN was enumerated or disconnected during development. No real Wazuh/Windows service was modified.

TRX evidence is in `artifacts/test-results/WazuhGuard.trx`. The Windows payload is in `artifacts/publish`. The expected future installer path is `artifacts/WazuhGuard-x64.msi`; that file is currently absent.

## Next command on Windows

Extract the complete source archive, install .NET SDK 10.0.301 or newer stable .NET 10 on the **build machine**, and run from the extracted root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

The script restores, builds, tests, publishes, compiles the WiX MSI and checks its service/payload/ACL/upgrade tables. The WiX project and PowerShell MSI inspector have not yet been executed successfully on native Windows; any resulting authoring or platform diagnostics must be resolved there before release. Run all of `LAB_TESTING.md`, including install, LocalSystem RAS visibility/hangup, reboot, crash recovery, uninstall, repair, upgrade, rollback and downgrade rejection. Sign the approved release using an organization-owned certificate if required.

New-install default is TestMode=true. Test and production use the same `%ProgramData%\WazuhGuard\appsettings.json`; change TestMode to false and restart WazuhGuard only when ready for real VPN disconnection. `-DefaultMode Production` builds a production-default MSI; it does not overwrite an existing customer's configuration.
