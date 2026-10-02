using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using WazuhGuard.Core;

namespace WazuhGuard.Vpn;

/// <summary>Check Point Remote Access VPN provider using the vendor-documented trac CLI.</summary>
public sealed class CheckPointVpnProvider(IVendorClientLocator locator, IVendorCommandRunner runner,
    GuardOptions options, TimeProvider time) : IVpnProvider
{
    public string Id => "CheckPoint";
    public VpnCapabilities Capabilities { get; } = new(true, true, true,
        "Documented trac.exe info / trac disconnect; disconnect is limited to one verified active site");

    public async Task<VpnProviderReport> DiscoverAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var client = locator.Find(Id);
        if (client is null) return new(Id, Capabilities with { DisconnectSessions = false }, VpnProviderState.NotInstalled,
            "trac.exe not found in known Program Files locations. This does not prove Check Point is absent; inspect Windows evidence below.", []);

        var result = await runner.RunAsync(client, ["info"], ct);
        var evidence = $"Executable: {client.Path}\nVersion: {client.Version}; product: {client.Product}; company: {client.Company}\nExit code: {result.ExitCode}; truncated: {result.Truncated}\ntrac info stdout:\n{result.Output}\ntrac info stderr:\n{result.Error}";
        if (result.ExitCode != 0 || result.Truncated || !string.IsNullOrWhiteSpace(result.Error))
            return new(Id, Capabilities with { DisconnectSessions = false }, VpnProviderState.Error,
                "trac info did not complete cleanly; connection state is unknown and disconnect is disabled.", [], evidence);

        try
        {
            var connected = ParseConnectedSites(result.Output);
            // trac disconnect without -g disconnects the active site. We authorize it only when
            // exactly one active Connected site was established by trac info, avoiding ambiguity.
            var canDisconnect = connected.Count == 1;
            var sessions = connected.Select(s => new VpnSession(Id, SessionId(s.Name, s.Gateway), s.Name, "Connected",
                "Check Point Remote Access VPN (trac CLI)", 0, Guid.Empty, false)
            {
                RemoteTunnelEndpoint = s.Gateway,
                DisconnectSupported = canDisconnect,
                DetectionMethod = "trac info: Conn block with status=Connected and active site=true"
            }).ToArray();
            return new(Id, Capabilities with { DisconnectSessions = canDisconnect }, VpnProviderState.Available,
                connected.Count == 0
                    ? "trac info completed successfully; no active Connected site was reported."
                    : canDisconnect
                        ? "One active Check Point site was verified. Vendor-documented trac disconnect is enabled (still blocked globally by TestMode)."
                        : "Multiple active Check Point sites were reported; generic active-site disconnect is disabled to avoid selecting the wrong tunnel.",
                sessions, evidence);
        }
        catch (InvalidDataException ex)
        {
            return new(Id, Capabilities with { DisconnectSessions = false }, VpnProviderState.Error,
                ex.Message + " No disconnect was authorized.", [], evidence);
        }
    }

    public async Task<DisconnectResult> DisconnectAsync(VpnSession session, CancellationToken ct)
    {
        if (options.TestMode) throw new InvalidOperationException("Disconnect is prohibited in TestMode.");
        if (session.Provider != Id || !session.DisconnectSupported)
            throw new NotSupportedException("Check Point session is not authorized for disconnect.");

        var client = locator.Find(Id) ?? throw new IOException("trac.exe is no longer installed.");
        var before = ParseConnectedSites((await RunInfoAsync(client, ct)).Output);
        if (!before.Any(s => SessionId(s.Name, s.Gateway) == session.Id)) return DisconnectResult.AlreadyGone;
        if (before.Count != 1)
            throw new InvalidOperationException("Check Point active-site set changed or is ambiguous; refusing disconnect.");

        ct.ThrowIfCancellationRequested();
        var result = await runner.RunAsync(client, ["disconnect"], ct);
        if (result.ExitCode != 0 || result.Truncated || !string.IsNullOrWhiteSpace(result.Error))
            throw new IOException($"Check Point trac disconnect failed: exit={result.ExitCode}; truncated={result.Truncated}; {result.Error}");

        var start = time.GetTimestamp();
        do
        {
            var after = ParseConnectedSites((await RunInfoAsync(client, ct)).Output);
            if (!after.Any(s => SessionId(s.Name, s.Gateway) == session.Id)) return DisconnectResult.Disconnected;
            await Task.Delay(TimeSpan.FromMilliseconds(250), time, ct);
        } while (time.GetElapsedTime(start) < TimeSpan.FromSeconds(options.VpnDisconnectTimeoutSeconds));
        throw new TimeoutException("Check Point site remained Connected after trac disconnect (it may have reconnected).");
    }

    private async Task<VendorCommandResult> RunInfoAsync(VendorClient client, CancellationToken ct)
    {
        var result = await runner.RunAsync(client, ["info"], ct);
        if (result.ExitCode != 0 || result.Truncated || !string.IsNullOrWhiteSpace(result.Error))
            throw new IOException($"Check Point trac info failed: exit={result.ExitCode}; truncated={result.Truncated}; {result.Error}");
        return result;
    }

    public static IReadOnlyList<(string Name, string Gateway)> ParseConnectedSites(string output)
    {
        var result = new List<(string Name, string Gateway)>();
        string? name = null, gateway = null, status = null;
        bool active = false;
        void Commit()
        {
            if (name is null) return;
            if (status?.Equals("Connected", StringComparison.OrdinalIgnoreCase) == true && active)
            {
                if (string.IsNullOrWhiteSpace(gateway)) throw new InvalidDataException("Connected Check Point site did not expose a gateway.");
                result.Add((name, gateway));
            }
            name = gateway = status = null; active = false;
        }

        foreach (var raw in output.Replace("\r", "").Split('\n'))
        {
            var line = raw.Trim();
            var m = Regex.Match(line, @"^Conn\s+(.+):$", RegexOptions.CultureInvariant);
            if (m.Success) { Commit(); name = m.Groups[1].Value.Trim(); continue; }
            if (name is null) continue;
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (key.Equals("gw", StringComparison.OrdinalIgnoreCase)) gateway = value;
            else if (key.Equals("status", StringComparison.OrdinalIgnoreCase)) status = value;
            else if (key.Equals("active site", StringComparison.OrdinalIgnoreCase))
                active = value.Equals("true", StringComparison.OrdinalIgnoreCase);
        }
        Commit();
        if (result.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != result.Count)
            throw new InvalidDataException("Ambiguous duplicate Check Point connection names.");
        return result;
    }

    private static string SessionId(string name, string gateway) =>
        "checkpoint:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name + "\n" + gateway)));
}
