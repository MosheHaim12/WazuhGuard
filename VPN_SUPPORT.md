# VPN providers and acceptance boundaries

The Windows service and all CLI commands resolve the same `CompositeVpnSessionManager` through `ProductionServices.AddWazuhGuardPrimitives`. It discovers registered `IVpnProvider` implementations, reports their capabilities/errors separately, and dispatches a selected session only to its owning provider. The Wazuh state machine is shared; its only provider-related change is skipping/reporting sessions whose disconnect capability is disabled.

| Provider | Detection | Disconnect mechanism | Current status |
| --- | --- | --- | --- |
| WindowsRAS | `RasEnumConnectionsW` + `RasGetConnectStatusW`; connected, error-free `vpn` entries only | `RasHangUpW` on the revalidated handle/correlation/name; wait for handle cleanup | Implemented; real VPN acceptance still required |
| CheckPoint | Known installed `trac.exe` + documented `info` output; Windows service/adapter evidence; RAS independently queried | None enabled in this build | Observation only; no authoritative parsed sessions or compatibility claim |
| FortiClient | Known `FortiVPN.exe`, file version 7.4.7, documented `--cli --status` records | `--cli --disconnect --tunnel <exact-profile-name>`; revalidate and poll status | Detection implemented for that narrow contract; disconnect disabled by default; real acceptance pending |
| Other VPNs | Heuristic service/adapter inventory when names identify VPN software | None | Unsupported/Unknown; no generic manipulation |

`TestMode=true` blocks every actual VPN disconnect, including CLI calls. FortiClient additionally requires `EnableFortiClientDisconnect=true`. Capabilities describe implemented operations, not certification; inspect the provider result as well (Available, ObservationOnly, NotInstalled, Unsupported, Error). A failure in one provider does not hide another provider's supported sessions. Inventory evidence is never converted into a connected session or permission to disconnect. No firewall, route, DNS, adapter, profile or credential modification is implemented.

## Check Point: first real-machine observation

On the Check Point-connected Windows machine run `--list-vpn` first using the waiting PowerShell invocation in [MANUAL_VALIDATION.md](MANUAL_VALIDATION.md). Expect raw `trac info` output when a recognized installation is available, plus any matching Windows service/adapter evidence and RAS sessions. **This machine has not been inspected yet.** An active Check Point tunnel is not guaranteed to appear in RAS or as a selectable session.

The locator examines Program Files and Program Files (x86) for `CheckPoint\Endpoint Connect\trac.exe`, `CheckPoint\Endpoint Security\Endpoint Connect\trac.exe`, and `CheckPoint\TRAC\trac.exe`. Other paths/editions are not automatically executed. Multiple matches, unexpected company metadata or reparse points produce an explicit error. Missing `trac.exe` means not found in these locations, not proof Check Point is absent.

Check Point documents both `trac info` and targeted `trac disconnect -g <gateway>`. This build deliberately implements only `info`: the client's real output format, active tunnel identity, gateway selection, version and account visibility still need evidence before a parser can authorize targeted disconnect. It never issues unqualified `trac disconnect`. Paste the full diagnostic output back to establish that mapping. Raw evidence may show site, gateway and connection state even though the structured supported-session count is zero.

## FortiClient: bounded initial contract

Only the documented **FortiClient Standalone Windows 7.4.7** CLI contract is implemented. Other file versions are reported Unsupported without execution. This does not imply support for every EMS-managed edition, client release or FortiGate configuration. A genuine supported installation may still expose different file-version metadata or localized output; those cases are refused until examined.

The parser accepts unambiguous `name :: state` records and returns only Connected profiles. Unrecognized/empty output, duplicate names, CLI errors or truncated output produce Unknown/error, not a guessed connected/disconnected state. Profile IDs are hashes of the profile name: they do not identify connection generations. Revalidation cannot eliminate a reconnect race on the same profile name. Targeted control always supplies `--tunnel`; the vendor's disconnect-all form is never used. Confirmation uses repeated status observations and a configured window; an individual CLI call has a ten-second deadline, so a status call may extend beyond the nominal polling window.

No FortiClient/FortiGate integration was exercised. Fake status samples test parsing, routing and safety gates only. Before production enablement, validate detection, target isolation with two profiles, reconnect behavior, CLI exit/output semantics, version matching and LocalSystem access on the actual client.

## RAS contract preserved

Unicode native functions are resolved only from System32. Discovery filters device type `vpn`, state `RASCS_Connected` and connection error zero. Modem/ISDN/PPPoE are excluded. The built-in IKEv2/SSTP/L2TP/PPTP client may be visible through RAS; this describes API scope, not a protocol recommendation or a claim of tested interoperability.

Metadata includes handle, correlation GUID, entry GUID, logon-session LUID, subentry, all-users flag, device description and available local/remote tunnel endpoints. Tunnel endpoints are not necessarily assigned VPN-internal addresses or configured gateway hostnames. Hangup re-enumerates and matches handle/correlation/name/type, then waits for `ERROR_INVALID_HANDLE`. Already disappeared sessions are benign; other errors/timeouts are explicit. Cleanup after an issued hangup remains bounded even during cancellation. Synchronous Windows APIs have OS-controlled call durations.

An empty RAS list does not prove that no VPN is connected. Interactive administrator visibility does not prove LocalSystem/session-zero or cross-user coverage. User profiles, device tunnels, concurrent users and automatic reconnection need separate acceptance. No impersonation or user-token acquisition is used. Successful handle cleanup is not packet-level isolation.

## Adding providers

Implement `IVpnProvider` with a distinct ID and explicit capabilities, then register it in `ProductionServices`. Supply stable identities, revalidate before targeted control, honor TestMode, bound external commands and retain the same shared state machine. Do not turn software/adapter evidence into control authority. Add contract tests and separate Windows/vendor acceptance evidence before claiming compatibility.

## Primary contracts

- Microsoft: [RasEnumConnectionsW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsw), [RASCONN](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376725(v=vs.85)), [RASCONNSTATUS](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376728(v=vs.85)), [RasHangUpW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupw).
- Check Point: [Remote Access Clients command line](https://sc1.checkpoint.com/documents/RemoteAccessClients_forWindows_AdminGuide/Content/Topics-RA-VPN-for-Win/Remote-Access-Clients-CMD.htm), [administrator guide, info/disconnect sections](https://sc1.checkpoint.com/documents/RemoteAccessClients_forWindows_AdminGuide/CP_RemoteAccess_VPN_Clients_forWin_AdminGuide.pdf).
- Fortinet: [FortiClient Standalone Windows 7.4.7 CLI commands](https://docs.fortinet.com/document/forticlient/7.4.7/forticlient-standalone-user-guide/95591/forticlient-standalone-windows-cli-commands).

Contracts reviewed for this implementation; none substitutes for real client acceptance.
