# Security boundary

WazuhGuard monitors **Wazuh Agent availability**: the configured service is Running and the configured installation directory exists. This does not prove executable authenticity, agent functionality, successful log collection, manager connectivity or absence of tampering.

WazuhGuard is **not tamper-proof against a malicious user with Local Administrator or SYSTEM privileges**. Such a user can stop either service, alter settings, replace binaries, interfere with RAS, uninstall WazuhGuard or repeatedly reset its grace period. The service is not a Protected Process Light service, kernel driver, VPN gateway control or remote compliance authority.

The MSI installs machine-wide under Program Files and sets protected ProgramData DACLs granting full control only to SYSTEM and Administrators. Configuration is immutable in-process, strictly validated on startup and is not read from user profile directories. A missing or invalid configuration prevents startup. Health/API uncertainty suspends enforcement instead of being converted into an outage. This availability-first rule means an attacker capable of making health queries fail may defer disconnection.

Only `ServiceController.Start` for the configured Wazuh service and `RasHangUpW` for verified active RAS VPN sessions change external system state during normal operation. Installation configures WazuhGuard's own service, files, event source and permissions. The application never edits firewall policy, routes, DNS, adapters, VPN profiles or credentials, and never establishes a VPN connection.

The distributed default configuration enables TestMode. Production is an explicit administrative configuration/release choice. TestMode still starts a stopped Wazuh service; it suppresses only VPN hangup. Logs contain connection names and identifiers and should remain restricted. Retained data is not erased on uninstall.

The .NET runtime is bundled, so patching the machine's separately installed .NET runtime does not patch this application. Build and deploy a new MSI with current stable .NET runtime/package patches as part of servicing. Increase the MSI version for each update. Apply organization-owned Authenticode signing using `scripts/build.ps1` when preparing an approved customer release.
