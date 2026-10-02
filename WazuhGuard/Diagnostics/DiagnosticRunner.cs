using WazuhGuard.Core;

namespace WazuhGuard.Diagnostics;

public sealed class DiagnosticRunner(IWazuhHealthMonitor health, IWazuhRecoveryService recovery,
    IVpnSessionManager vpn, GuardOptions options, TextWriter output)
{
    public async Task<int> RunAsync(DiagnosticCommand command, CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            return command.Operation switch
            {
                DiagnosticOperation.Help => PrintHelp(),
                DiagnosticOperation.CheckWazuh => HealthExitCode(await CheckAsync(ct)),
                DiagnosticOperation.ListVpn => await ListAsync(ct),
                DiagnosticOperation.DisconnectVpn => await DisconnectAsync(command.Identifier, ct),
                DiagnosticOperation.CheckAndRepairWazuh => await RepairAsync(ct),
                _ => throw new ArgumentException("Unsupported diagnostic operation.")
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            output.WriteLine("CANCELLED: no further operations requested. A hangup already issued cannot be undone.");
            return 130;
        }
        catch (Exception ex)
        {
            output.WriteLine($"FAIL: diagnostic operation failed. Error: {ex}");
            return 3;
        }
    }

    private int PrintHelp() { output.WriteLine(DiagnosticCommand.Help); return 0; }
    private static int HealthExitCode(HealthSnapshot result) => result.IsHealthy ? 0 : result.IsVerifiedUnhealthy ? 1 : 3;
    private async Task<HealthSnapshot> CheckAsync(CancellationToken ct)
    {
        HealthSnapshot result;
        Exception? error = null;
        try { result = await health.CheckAsync(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HealthCheckException ex) { result = ex.Snapshot; error = ex; }
        catch (Exception ex) { result = new(HealthStatus.Unknown, "Health observation failed"); error = ex; }
        var details = result.Diagnostics;
        output.WriteLine($"Service name: {options.WazuhServiceName}");
        output.WriteLine($"Service exists: {YesNo(details?.ServiceExists)}");
        output.WriteLine($"Windows service state: {details?.ServiceState ?? "Unknown"}");
        output.WriteLine($"Installation directory: {options.WazuhInstallPath}");
        output.WriteLine($"Installation directory exists: {YesNo(details?.InstallationDirectoryExists)}");
        output.WriteLine($"Installation directory accessible (attribute query): {YesNo(details?.InstallationAccessible)}");
        output.WriteLine($"Overall health: {(result.IsHealthy ? "Healthy" : result.IsVerifiedUnhealthy ? "Unhealthy" : "Unknown")} ({result.Status})");
        output.WriteLine($"Reason: {result.Detail}");
        output.WriteLine($"Error: {error?.ToString() ?? "None"}");
        return result;
    }

    private async Task<int> RepairAsync(CancellationToken ct)
    {
        output.WriteLine("Initial production health check:");
        var initial = await CheckAsync(ct);
        if (initial.IsHealthy) { output.WriteLine("PASS: Wazuh is Healthy. No recovery requested."); return 0; }
        if (initial.Status != HealthStatus.Stopped)
        {
            output.WriteLine("No recovery requested: health must establish a stopped service and present installation. Wazuh is never reinstalled.");
            return HealthExitCode(initial);
        }
        output.WriteLine($"Invoking production recovery: {options.RestartAttempts} attempts; {options.RestartTimeoutSeconds}s timeout per attempt; {options.RestartDelaySeconds}s retry delay.");
        Exception? recoveryError = null;
        try { output.WriteLine($"Recovery primitive result: {await recovery.TryRecoverAsync(ct)}"); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { recoveryError = ex; output.WriteLine($"Recovery error: {ex}"); }
        output.WriteLine("Post-recovery production health check:");
        var final = await CheckAsync(ct);
        output.WriteLine(final.IsHealthy && recoveryError is null
            ? "PASS: post-recovery check verifies Wazuh is Healthy."
            : "FAIL: recovery did not complete with verified Healthy status.");
        return recoveryError is not null ? 3 : HealthExitCode(final);
    }

    private async Task<int> ListAsync(CancellationToken ct)
    {
        var report = await vpn.DiscoverAsync(ct);
        PrintReport(report);
        return report.Providers.Any(p => p.State == VpnProviderState.Error) ? 3 : 0;
    }

    private async Task<int> DisconnectAsync(string? identifier, CancellationToken ct)
    {
        var discovery = await vpn.DiscoverAsync(ct);
        var sessions = discovery.Sessions;
        PrintReport(discovery);
        VpnSession? selected;
        if (identifier is null)
        {
            if (sessions.Count != 1)
            {
                output.WriteLine(sessions.Count == 0 ? "FAIL: no session to disconnect." : "FAIL: multiple sessions; supply a unique session ID or profile name. Nothing was disconnected.");
                return 2;
            }
            selected = sessions[0];
        }
        else
        {
            var matches = sessions.Where(s => s.Id.Equals(identifier, StringComparison.Ordinal)).ToArray();
            if (matches.Length == 0) matches = sessions.Where(s => s.Name.Equals(identifier, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length != 1)
            {
                output.WriteLine("FAIL: identifier did not match exactly one active session. Use the full session ID from --list-vpn. Nothing was disconnected.");
                return 2;
            }
            selected = matches[0];
        }
        output.WriteLine("Selected session for disconnection:");
        PrintSession(selected);
        output.Flush(); // Selection must be visible before the changing operation.
        if (!selected.DisconnectSupported)
        {
            output.WriteLine("FAIL (unsupported): this provider/session is detection-only or disconnect is disabled. No generic network action is permitted.");
            return 4;
        }
        if (options.TestMode)
        {
            output.WriteLine("FAIL (blocked): TestMode=true. The production safety check prohibits disconnect. Change the lab configuration to TestMode=false; no override is provided.");
            return 4;
        }
        ct.ThrowIfCancellationRequested();
        Exception? disconnectError = null;
        try { output.WriteLine($"Production disconnect result: {await vpn.DisconnectVpnSessionAsync(selected, ct)}"); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { disconnectError = ex; output.WriteLine($"Disconnect error: {ex}"); }
        output.WriteLine("Re-enumerating through the production VPN provider:");
        var verification = await vpn.DiscoverAsync(ct);
        PrintReport(verification);
        if (verification.Providers.Any(p => p.Provider == selected.Provider && p.State != VpnProviderState.Available))
        {
            output.WriteLine("FAIL: the owning provider could not verify connection state after disconnect.");
            return 3;
        }
        var after = verification.Sessions;
        if (after.Any(s => s.Provider == selected.Provider && s.Id == selected.Id))
        {
            output.WriteLine("FAIL: selected session is still reported active.");
            return 5;
        }
        var reconnected = after.Where(s => s.Provider == selected.Provider && s.Name.Equals(selected.Name, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (reconnected.Length > 0)
            output.WriteLine("A different session with the same profile name is active (possible automatic reconnection). It was not disconnected.");
        if (disconnectError is not null)
        {
            output.WriteLine("FAIL: selected session is now absent, but the disconnect primitive reported an error. Success cannot be attributed to this command.");
            return 3;
        }
        output.WriteLine("PASS: selected session is absent from its provider's active VPN list. This does not assert packet-level isolation or absence of other VPN clients.");
        return 0;
    }

    private void PrintSessions(IReadOnlyList<VpnSession> sessions)
    {
        output.WriteLine($"Supported active VPN sessions: {sessions.Count}");
        if (sessions.Count == 0) output.WriteLine("No supported VPN sessions were detected in this account context. Review provider/evidence results; this does not prove that no VPN is connected.");
        foreach (var session in sessions) PrintSession(session);
    }
    private void PrintSession(VpnSession session)
    {
        output.WriteLine($"  Name: {session.Name}");
        output.WriteLine($"  Session ID: {session.Id}");
        output.WriteLine($"  Provider: {session.Provider}; state: {session.Status}; handle: 0x{session.Handle:x}");
        output.WriteLine($"  Detection method: {session.DetectionMethod}; disconnect supported/enabled: {session.DisconnectSupported}");
        output.WriteLine($"  Device type: {session.DeviceType ?? "Not provided"}; device name: {session.DeviceName ?? "Not provided"}");
        output.WriteLine($"  Technology description: {session.Technology}");
        output.WriteLine($"  Local tunnel endpoint: {session.LocalTunnelEndpoint ?? "Not provided by this provider"}");
        output.WriteLine($"  Remote tunnel endpoint: {session.RemoteTunnelEndpoint ?? "Not provided by this provider"}");
        output.WriteLine("  Assigned VPN-internal address / configured server hostname: not exposed by this provider; tunnel endpoints are not assigned addresses.");
        output.WriteLine($"  Correlation ID: {session.CorrelationId}; entry ID: {session.EntryId?.ToString() ?? "Not provided"}");
        output.WriteLine($"  All-users connection: {session.AllUsers}; logon session LUID: {session.LogonSessionId?.ToString("x") ?? "Not provided"}; subentry: {session.SubEntry?.ToString() ?? "Not provided"}");
    }
    private void PrintReport(VpnDiscoveryReport report)
    {
        foreach (var provider in report.Providers)
        {
            output.WriteLine($"Provider: {provider.Provider}; result: {provider.State}");
            output.WriteLine($"  Capabilities: detect sessions={provider.Capabilities.DetectSessions}; metadata={provider.Capabilities.ReadMetadata}; disconnect={provider.Capabilities.DisconnectSessions}");
            output.WriteLine($"  Mechanism: {provider.Capabilities.Mechanism}\n  Detail: {provider.Detail}");
            if (provider.Evidence is not null)
                output.WriteLine("  Read-only vendor evidence (not proof of supported session control):\n" +
                    new string(provider.Evidence.Where(c => !char.IsControl(c) || c is '\n' or '\r' or '\t').ToArray()));
        }
        PrintSessions(report.Sessions);
        foreach (var evidence in report.Evidence)
            output.WriteLine($"Windows evidence: {evidence.Vendor}; {evidence.Kind}; {evidence.Name}; state={evidence.State}; {evidence.Detail}");
        if (report.Evidence.Count > 0) output.WriteLine("Windows software/service/adapter evidence does not prove an active tunnel and never authorizes disconnect.");
    }
    private static string YesNo(bool? value) => value is null ? "Unknown / not established" : value.Value ? "Yes" : "No";
}
