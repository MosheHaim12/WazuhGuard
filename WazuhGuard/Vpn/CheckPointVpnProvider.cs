using WazuhGuard.Core;

namespace WazuhGuard.Vpn;

/// <summary>Read-only vendor evidence. No unverified text-to-session mapping authorizes hangup.</summary>
public sealed class CheckPointVpnProvider(IVendorClientLocator locator, IVendorCommandRunner runner) : IVpnProvider
{
    public string Id => "CheckPoint";
    public VpnCapabilities Capabilities { get; } = new(false, true, false, "Documented trac.exe info; raw site/gateway/tunnel evidence, not parsed into authoritative sessions");
    public async Task<VpnProviderReport> DiscoverAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var client = locator.Find(Id);
        if (client is null) return new(Id, Capabilities, VpnProviderState.NotInstalled,
            "trac.exe not found in known Program Files locations. This does not prove Check Point is absent; inspect Windows evidence below.", []);
        var result = await runner.RunAsync(client, ["info"], ct);
        var evidence = $"Executable: {client.Path}\nVersion: {client.Version}; product: {client.Product}; company: {client.Company}\nExit code: {result.ExitCode}; truncated: {result.Truncated}\ntrac info stdout:\n{result.Output}\ntrac info stderr:\n{result.Error}";
        return new(Id, Capabilities, result.ExitCode == 0 && !result.Truncated && string.IsNullOrWhiteSpace(result.Error) ? VpnProviderState.ObservationOnly : VpnProviderState.Error,
            "Check Point supplies read-only tunnel information. Its output/gateway identity has not been validated on the lab client; safe targeted disconnect is not enabled. No trac disconnect, service stop or adapter action is issued.", [], evidence);
    }
    public Task<DisconnectResult> DisconnectAsync(VpnSession session, CancellationToken ct) =>
        throw new NotSupportedException("Check Point is observation-only until real trac info output establishes reliable tunnel selection; no generic fallback is permitted.");
}
