namespace WazuhGuard.Diagnostics;

public enum DiagnosticOperation { Help, CheckWazuh, ListVpn, DisconnectVpn, CheckAndRepairWazuh }
public sealed record DiagnosticCommand(DiagnosticOperation Operation, string? Identifier = null)
{
    public static DiagnosticCommand Parse(string[] args) => args switch
    {
        ["--help"] => new(DiagnosticOperation.Help),
        ["--check-wazuh"] => new(DiagnosticOperation.CheckWazuh),
        ["--list-vpn"] => new(DiagnosticOperation.ListVpn),
        ["--disconnect-vpn"] => new(DiagnosticOperation.DisconnectVpn),
        ["--disconnect-vpn", var id] when !string.IsNullOrWhiteSpace(id) && !id.StartsWith("--", StringComparison.Ordinal)
            => new(DiagnosticOperation.DisconnectVpn, id),
        ["--check-and-repair-wazuh"] => new(DiagnosticOperation.CheckAndRepairWazuh),
        _ => throw new ArgumentException("Unknown command, extra arguments or empty identifier. Use --help.")
    };

    public const string Help = """
        WazuhGuard manual diagnostics (uses the production primitives; no automatic enforcement loop)
          --check-wazuh                    Read-only Wazuh health observation
          --list-vpn                       Read-only multi-provider VPN discovery and vendor evidence
          --disconnect-vpn [ID or name]     Disconnect one session; requires TestMode=false
          --check-and-repair-wazuh          Recover only verified stopped Wazuh, then recheck
          --help                           Show commands without reading configuration
        Multiple VPN sessions require a unique exact session ID or unique profile name.
        Configuration: %ProgramData%\WazuhGuard\appsettings.json (same as the service).
        Check Point: observation-only. FortiClient: 7.4.7 CLI contract, disconnect opt-in.
        Unsupported vendor/adapter evidence never authorizes a generic disconnect.
        Commands use the current account; visibility can differ from LocalSystem.
        WinExe host: use Start-Process -Wait -NoNewWindow -PassThru in PowerShell for a reliable exit code.
        Exit codes: 0 PASS/healthy/list completed; 1 unhealthy; 2 usage; 3 unknown/API/config error;
                    4 disconnect blocked/unsupported; 5 disconnect verification failed; 130 cancelled.
        """;
}
