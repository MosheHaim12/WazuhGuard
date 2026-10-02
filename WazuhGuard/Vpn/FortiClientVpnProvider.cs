using System.Security.Cryptography;
using System.Text;
using WazuhGuard.Core;

namespace WazuhGuard.Vpn;

/// <summary>Implements only the documented FortiClient Standalone Windows 7.4.7 CLI contract.</summary>
public sealed class FortiClientVpnProvider(IVendorClientLocator locator, IVendorCommandRunner runner,
    GuardOptions options, TimeProvider time) : IVpnProvider
{
    public string Id => "FortiClient";
    public VpnCapabilities Capabilities => new(true, true, options.EnableFortiClientDisconnect,
        "FortiVPN.exe --cli --status; targeted --disconnect --tunnel (7.4.7 CLI contract; real interoperability unverified)");

    public async Task<VpnProviderReport> DiscoverAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var client = locator.Find(Id);
        if (client is null) return new(Id, Capabilities with { DisconnectSessions = false }, VpnProviderState.NotInstalled,
            "FortiVPN.exe not found in known Program Files locations; inspect Windows evidence for other editions/installations.", []);
        if (!SupportedVersion(client)) return new(Id, Capabilities with { DisconnectSessions = false }, VpnProviderState.Unsupported,
            $"Found {client.Path}, version {client.Version}. Only the documented 7.4.7 CLI contract is implemented; no vendor command was executed.", []);
        var raw = await runner.RunAsync(client, ["--cli", "--status"], ct);
        var evidence = $"Executable: {client.Path}\nVersion: {client.Version}; product: {client.Product}\nExit code: {raw.ExitCode}; truncated: {raw.Truncated}\nstdout:\n{raw.Output}\nstderr:\n{raw.Error}";
        try
        {
            EnsureSuccess(raw);
            var states = ParseStatus(raw.Output);
            var sessions = states.Where(s => s.State == "Connected").Select(s => new VpnSession(Id,
                SessionId(s.Name), s.Name, s.State, "FortiClient 7.4.7 CLI (protocol not supplied)", 0, Guid.Empty, false)
            {
                DisconnectSupported = options.EnableFortiClientDisconnect,
                DetectionMethod = "FortiVPN.exe --cli --status; exact documented name :: state records"
            }).ToArray();
            return new(Id, Capabilities, VpnProviderState.Available,
                "Only Connected records are sessions. IDs identify profiles, not connection generations. Detection is not real-machine validation. Targeted disconnect is opt-in via EnableFortiClientDisconnect.", sessions, evidence);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        { return new(Id, Capabilities with { DisconnectSessions = false }, VpnProviderState.Error, ex.Message, [], evidence); }
    }

    public async Task<DisconnectResult> DisconnectAsync(VpnSession session, CancellationToken ct)
    {
        if (options.TestMode) throw new InvalidOperationException("Disconnect is prohibited in TestMode.");
        if (!options.EnableFortiClientDisconnect) throw new NotSupportedException("FortiClient disconnect is disabled until explicitly enabled for lab acceptance.");
        if (session.Provider != Id || session.Id != SessionId(session.Name)) throw new ArgumentException("Session does not belong to this FortiClient provider.");
        var client = locator.Find(Id) ?? throw new IOException("FortiVPN.exe is no longer installed.");
        if (!SupportedVersion(client)) throw new NotSupportedException("FortiClient version does not match the implemented CLI contract.");
        var before = await ReadStatusAsync(client, ct);
        if (!before.Any(s => s.Name == session.Name && s.State == "Connected")) return DisconnectResult.AlreadyGone;
        ct.ThrowIfCancellationRequested();
        // A tunnel name is always supplied. Never issue the vendor's disconnect-all form.
        EnsureSuccess(await runner.RunAsync(client, ["--cli", "--disconnect", "--tunnel", session.Name], ct));
        var start = time.GetTimestamp();
        do
        {
            var states = await ReadStatusAsync(client, ct);
            if (!states.Any(s => s.Name == session.Name && s.State != "Disconnected")) return DisconnectResult.Disconnected;
            await Task.Delay(TimeSpan.FromMilliseconds(250), time, ct);
        } while (time.GetElapsedTime(start) < TimeSpan.FromSeconds(options.VpnDisconnectTimeoutSeconds));
        throw new TimeoutException("FortiClient profile did not reach Disconnected within the confirmation window (it may have reconnected).");
    }

    private async Task<IReadOnlyList<(string Name, string State)>> ReadStatusAsync(VendorClient client, CancellationToken ct)
    {
        var result = await runner.RunAsync(client, ["--cli", "--status"], ct);
        EnsureSuccess(result);
        return ParseStatus(result.Output);
    }
    public static IReadOnlyList<(string Name, string State)> ParseStatus(string output)
    {
        var result = new List<(string Name, string State)>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("FortiClient VPN 7.4.7", StringComparison.Ordinal)) continue;
            var pieces = line.Split(" :: ", StringSplitOptions.None);
            if (pieces.Length != 2 || string.IsNullOrWhiteSpace(pieces[0]) || pieces[0].Length > 256 ||
                pieces[0].StartsWith('-') || pieces[0].Any(char.IsControl) ||
                pieces[1] is not ("Connected" or "Disconnected" or "Connecting" or "Disconnecting"))
                throw new InvalidDataException("Unrecognized FortiClient status output; refusing to infer sessions or authorize a disconnect.");
            result.Add((pieces[0], pieces[1]));
        }
        if (result.Count == 0 || result.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != result.Count)
            throw new InvalidDataException("Empty or ambiguous FortiClient status output; connection state is unknown.");
        return result;
    }
    private static bool SupportedVersion(VendorClient client) => client.Version.Major == 7 && client.Version.Minor == 4 && client.Version.Build == 7;
    private static string SessionId(string name) => "forti-profile:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name)));
    private static void EnsureSuccess(VendorCommandResult result)
    {
        if (result.ExitCode != 0 || result.Truncated || !string.IsNullOrWhiteSpace(result.Error))
            throw new IOException($"FortiClient CLI error {result.ExitCode}; truncated={result.Truncated}; {result.Error}");
    }
}
