# VPN support and native API contract

## Implemented scope

The production provider calls Unicode `RasEnumConnectionsW`, `RasGetConnectStatusW`, and `RasHangUpW` in Windows `rasapi32.dll` through P/Invoke. DLL lookup is limited to System32. Only entries whose RAS device type equals `vpn`, whose state equals `RASCS_Connected` (0x2000), and whose connection error is zero are eligible. Ordinary modem, ISDN, PPPoE and other non-VPN RAS connections are excluded.

This supports the Windows built-in **IKEv2, SSTP, L2TP/IPsec and PPTP client sessions when they are exposed as active RAS VPN connections to the LocalSystem service**. Listing PPTP/L2TP describes API compatibility, not a recommendation to deploy those protocols. There is no protocol-specific credential/profile manipulation. Device name is logged as descriptive technology metadata; it is not parsed into an authoritative protocol claim.

Enumeration returns session name, connected status, opaque native handle, correlation GUID, device description and all-users flag. No phonebook, password or credential is changed. Before hangup, the provider re-enumerates and matches handle, correlation ID, name and VPN type to reduce stale-handle/reconnection races. `RasHangUpW` disconnects that session; success is reported only after status returns `ERROR_INVALID_HANDLE`. Already disappeared sessions are benign. Other native errors and bounded cleanup timeouts are logged and retried in later monitoring cycles.

Microsoft documents that RAS enumeration is followed by a status check to establish current connection state, and that hangup cleanup is asynchronous. The implementation follows both contracts. Enumeration allocation/retry counts, recovery polling and disconnect cleanup are bounded. After hangup has been issued, cancellation does not interrupt the bounded cleanup window (default 10 seconds, maximum 60), so SCM shutdown grants up to 90 seconds. Native synchronous API calls themselves have Windows-managed execution times; a managed cancellation token cannot interrupt a native call already in progress.

## Limitations and required acceptance evidence

* RAS is not a universal inventory of every encrypted tunnel or network adapter. An empty RAS list means **no supported visible active RAS VPN**, not proof that the endpoint has no VPN.
* No vendor integration is implemented for FortiClient, Cisco Secure Client/AnyConnect, Palo Alto GlobalProtect, Check Point, OpenVPN, WireGuard, Tailscale or other independent clients. Those commonly require vendor-supported APIs. No arbitrary process killing or adapter disabling substitutes for an integration.
* UWP/plugin-backed VPNs may use the Windows VPN platform but expose different behavior/technology labels. They are not independently certified here. A device described as SSTP may belong to a plugin using a different protocol.
* LocalSystem/session-zero visibility and permissions must be verified on the actual deployment. Test user-only profiles, all-user profiles, concurrent user sessions and any Always On device/user tunnels separately. No impersonation, user token acquisition or RAS server administration API is used to extend visibility. Do not infer complete cross-user coverage from an interactive administrator's successful enumeration.
* Always On/auto-trigger clients can reconnect immediately. WazuhGuard disconnects supported sessions again after its next poll; it does not disable auto-connect policy. Fast reconnect loops can produce repeated disconnect logs and short connection windows.
* RAS call acceptance is not proof that every packet has stopped. The implementation confirms handle cleanup; VPN and network behavior require the lab checks.
* Admins/SYSTEM can stop the guard, change configuration or replace binaries. There is no tamper-proof claim.

No real VPN protocol/interoperability test is claimed by the automated suite. Each intended OS/profile/protocol must pass the LocalSystem tests in `LAB_TESTING.md` before being described as deployment-validated.

## Extending providers

Implement `IVpnSessionManager` using the vendor's supported session API, provide a distinct `VpnSession.Provider` value and stable per-connection identity, and register a composite dispatcher in `Program.cs`. The current provider rejects another provider's sessions. Maintain TestMode suppression, cancellation, bounded execution, per-session result logging and revalidation. Add fake API contract tests plus separate disposable-VM integration evidence before enabling a vendor provider.

## Primary references

* Microsoft: [RasEnumConnectionsW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsw), active list, sizing, status-check requirement.
* Microsoft: [RASCONN layout](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376725(v=vs.85)), handle, device type, flags and correlation ID.
* Microsoft: [RASCONNSTATUS layout](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376728(v=vs.85)), connected state, error and tunnel fields.
* Microsoft: [RasHangUpW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupw), session hangup and asynchronous cleanup.
* Microsoft: [VPN connection types](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-connection-type), built-in protocols and plugin platform distinction.

Reviewed for this implementation on 2026-09-30. References explain the API contract; they do not certify this application's runtime interoperability.
