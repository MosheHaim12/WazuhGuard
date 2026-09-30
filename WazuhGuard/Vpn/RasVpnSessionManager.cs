using System.ComponentModel;
using WazuhGuard.Core;

namespace WazuhGuard.Vpn;

public sealed class RasVpnSessionManager(IRasApi api, GuardOptions options, TimeProvider time,
    ILogger<RasVpnSessionManager> log) : IVpnSessionManager, IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    public async Task<IReadOnlyList<VpnSession>> GetActiveVpnSessionsAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            var sessions = new List<VpnSession>();
            foreach (var item in api.Enumerate())
            {
                ct.ThrowIfCancellationRequested();
                // RAS also manages modem, PPPoE and other non-VPN connections. Leave them alone.
                if (!IsVpn(item)) continue;
                var status = api.GetStatus(item.Handle);
                if (status.ErrorCode == NativeRasApi.InvalidHandle) continue;
                ThrowIfError(status.ErrorCode, "RasGetConnectStatusW");
                if (status.State != NativeRasApi.Connected || status.ConnectionError != 0) continue;
                sessions.Add(new("WindowsRAS", Id(item), item.Name, "Connected",
                    $"Windows RAS VPN ({item.DeviceName})", item.Handle, item.CorrelationId, item.AllUsers));
            }
            return sessions;
        }
        finally { gate.Release(); }
    }

    public async Task<DisconnectResult> DisconnectVpnSessionAsync(VpnSession session, CancellationToken ct)
    {
        // Defense in depth: direct callers cannot bypass TestMode.
        if (options.TestMode) throw new InvalidOperationException("Disconnect is prohibited in TestMode.");
        if (session.Provider != "WindowsRAS") throw new ArgumentException("Session belongs to another VPN provider.", nameof(session));
        await gate.WaitAsync(ct);
        try
        {
            ct.ThrowIfCancellationRequested();
            // Re-enumerate before using the handle: a disconnected session's handle may be recycled.
            var current = api.Enumerate().FirstOrDefault(c => IsVpn(c) && c.Handle == session.Handle &&
                c.CorrelationId == session.CorrelationId && c.Name == session.Name && Id(c) == session.Id);
            if (current is null) return DisconnectResult.AlreadyGone;
            var status = api.GetStatus(current.Handle);
            if (status.ErrorCode == NativeRasApi.InvalidHandle) return DisconnectResult.AlreadyGone;
            ThrowIfError(status.ErrorCode, "RasGetConnectStatusW");
            if (status.State != NativeRasApi.Connected || status.ConnectionError != 0) return DisconnectResult.AlreadyGone;
            ct.ThrowIfCancellationRequested();
            var result = api.HangUp(current.Handle);
            if (result == NativeRasApi.InvalidHandle) return DisconnectResult.AlreadyGone;
            ThrowIfError(result, "RasHangUpW");
            // RAS hangup is asynchronous. Once issued, allow bounded cleanup even during service stop.
            var started = time.GetTimestamp();
            while (time.GetElapsedTime(started) < TimeSpan.FromSeconds(options.VpnDisconnectTimeoutSeconds))
            {
                status = api.GetStatus(current.Handle);
                if (status.ErrorCode == NativeRasApi.InvalidHandle) return DisconnectResult.Disconnected;
                ThrowIfError(status.ErrorCode, "RasGetConnectStatusW after hangup");
                await Task.Delay(TimeSpan.FromMilliseconds(100), time, CancellationToken.None);
            }
            log.LogWarning("RAS accepted hangup but handle cleanup timed out for {VpnId}", session.Id);
            throw new TimeoutException("RAS hangup cleanup did not finish within the configured deadline.");
        }
        finally { gate.Release(); }
    }

    private static bool IsVpn(RasConnection connection) => connection.DeviceType.Equals("vpn", StringComparison.OrdinalIgnoreCase);
    private static string Id(RasConnection connection) => $"ras:{connection.Handle:x}:{connection.CorrelationId:D}";
    private static void ThrowIfError(uint error, string operation)
    {
        if (error != NativeRasApi.Success) throw new Win32Exception((int)error, $"{operation} failed ({error}).");
    }
    public void Dispose() => gate.Dispose();
}
