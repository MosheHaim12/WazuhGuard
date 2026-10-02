using WazuhGuard.Core;

namespace WazuhGuard.Vpn;

public interface IVpnEnvironmentProbe
{
    IReadOnlyList<VpnEvidence> Inspect(CancellationToken ct);
}

public sealed class CompositeVpnSessionManager(IEnumerable<IVpnProvider> providers, IVpnEnvironmentProbe environment,
    GuardOptions options, ILogger<CompositeVpnSessionManager> log) : IVpnSessionManager, IDisposable
{
    private readonly Dictionary<string, IVpnProvider> providersById = providers.ToDictionary(p => p.Id, StringComparer.Ordinal);
    private readonly Dictionary<string, string> lastReport = [];
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<VpnDiscoveryReport> DiscoverAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            var reports = new List<VpnProviderReport>();
            foreach (var provider in providersById.Values)
            {
                ct.ThrowIfCancellationRequested();
                VpnProviderReport report;
                try
                {
                    report = await provider.DiscoverAsync(ct);
                    if (report.Provider != provider.Id || report.Sessions.Any(s => s.Provider != provider.Id))
                        throw new InvalidDataException("VPN provider returned a session owned by a different provider.");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { report = new(provider.Id, provider.Capabilities, VpnProviderState.Error, ex.ToString(), []); }
                reports.Add(report);
                var signature = $"{report.State}:{report.Detail}";
                if (lastReport.GetValueOrDefault(provider.Id) != signature)
                {
                    log.LogInformation("VPN provider {Provider}: {State}; {Detail}; disconnect capability {DisconnectSupported}",
                        provider.Id, report.State, report.Detail, report.Capabilities.DisconnectSessions);
                    lastReport[provider.Id] = signature;
                }
            }
            IReadOnlyList<VpnEvidence> evidence;
            try { evidence = environment.Inspect(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { evidence = [new("Unknown", "InventoryError", "Windows inventory", "Unknown", ex.ToString())]; }
            // Software/adapter evidence is deliberately not converted into a connected session.
            return new(reports.SelectMany(r => r.Sessions).ToArray(), reports, evidence);
        }
        finally { gate.Release(); }
    }

    public async Task<IReadOnlyList<VpnSession>> GetActiveVpnSessionsAsync(CancellationToken ct) => (await DiscoverAsync(ct)).Sessions;
    public async Task<DisconnectResult> DisconnectVpnSessionAsync(VpnSession session, CancellationToken ct)
    {
        if (options.TestMode) throw new InvalidOperationException("Disconnect is prohibited in TestMode.");
        if (!providersById.TryGetValue(session.Provider, out var provider)) throw new NotSupportedException("Unknown VPN provider; no generic disconnect fallback exists.");
        if (!session.DisconnectSupported || !provider.Capabilities.DisconnectSessions)
            throw new NotSupportedException($"{session.Provider} session disconnection is unsupported or disabled.");
        await gate.WaitAsync(ct);
        try { return await provider.DisconnectAsync(session, ct); }
        finally { gate.Release(); }
    }
    public void Dispose() => gate.Dispose();
}

public sealed class RasVpnProvider(RasVpnSessionManager ras) : IVpnProvider
{
    public string Id => "WindowsRAS";
    public VpnCapabilities Capabilities { get; } = new(true, true, true, "RasEnumConnectionsW / RasGetConnectStatusW / RasHangUpW");
    public async Task<VpnProviderReport> DiscoverAsync(CancellationToken ct) => new(Id, Capabilities, VpnProviderState.Available,
        "Active VPN-type RAS connections visible to this account; not a universal VPN inventory.", await ras.GetActiveVpnSessionsAsync(ct));
    public Task<DisconnectResult> DisconnectAsync(VpnSession session, CancellationToken ct) => ras.DisconnectVpnSessionAsync(session, ct);
}
