using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging.Abstractions;
using WazuhGuard.Core;
using WazuhGuard.Monitoring;
using WazuhGuard.Recovery;
using WazuhGuard.Vpn;

namespace WazuhGuard.Tests;

public sealed class WindowsProvidersTests
{
    [Theory]
    [InlineData(WazuhServiceStatus.Running, true, HealthStatus.Healthy)]
    [InlineData(WazuhServiceStatus.Stopped, true, HealthStatus.Stopped)]
    [InlineData(WazuhServiceStatus.Missing, true, HealthStatus.ServiceMissing)]
    [InlineData(WazuhServiceStatus.Running, false, HealthStatus.InstallationMissing)]
    [InlineData(WazuhServiceStatus.Pending, true, HealthStatus.Pending)]
    public async Task HealthRequiresServiceAndDirectory(WazuhServiceStatus status, bool exists, HealthStatus expected)
    {
        var monitor = new WazuhHealthMonitor(new FakeService { Status = status }, new FakeInstallation { Present = exists });
        Assert.Equal(expected, (await monitor.CheckAsync(default)).Status);
    }

    [Fact] public async Task AccessDeniedIsNotReportedAsMissing()
    {
        var monitor = new WazuhHealthMonitor(new FakeService { Error = new Win32Exception(5) }, new FakeInstallation());
        await Assert.ThrowsAsync<Win32Exception>(() => monitor.CheckAsync(default));
    }

    [Fact] public async Task RecoveryStartsStoppedService()
    {
        var service = new FakeService { Status = WazuhServiceStatus.Stopped, StartWorks = true };
        using var recovery = Recovery(service);
        Assert.True(await recovery.TryRecoverAsync(default));
        Assert.Equal(1, service.Starts);
    }

    [Fact] public async Task RecoveryDoesNotRecreateMissingService()
    {
        var service = new FakeService { Status = WazuhServiceStatus.Missing };
        using var recovery = Recovery(service);
        Assert.False(await recovery.TryRecoverAsync(default));
        Assert.Equal(0, service.Starts);
    }

    [Fact] public async Task RecoveryRetriesConfiguredNumberOfTimes()
    {
        var service = new FakeService { Status = WazuhServiceStatus.Stopped };
        using var recovery = Recovery(service);
        Assert.False(await recovery.TryRecoverAsync(default));
        Assert.Equal(3, service.Starts);
    }

    [Fact] public async Task RecoveryObservesCancellationDuringDelay()
    {
        var service = new FakeService { Status = WazuhServiceStatus.Stopped };
        using var recovery = Recovery(service);
        using var cts = new CancellationTokenSource();
        service.OnStart = () => cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => recovery.TryRecoverAsync(cts.Token));
        Assert.Equal(1, service.Starts);
    }

    [Fact] public void NativeStructLayoutMatchesWindowsX64Abi()
    {
        Assert.Equal(8, IntPtr.Size);
        Assert.Equal(1392, Marshal.SizeOf<NativeRasApi.RasConn>());
        Assert.Equal(8, Marshal.OffsetOf<NativeRasApi.RasConn>(nameof(NativeRasApi.RasConn.Handle)).ToInt32());
        Assert.Equal(1376, Marshal.OffsetOf<NativeRasApi.RasConn>(nameof(NativeRasApi.RasConn.CorrelationId)).ToInt32());
        Assert.Equal(608, Marshal.SizeOf<NativeRasApi.RasConnStatus>());
        Assert.Equal(564, Marshal.OffsetOf<NativeRasApi.RasConnStatus>(nameof(NativeRasApi.RasConnStatus.Local)).ToInt32());
    }

    [Fact] public async Task RasFiltersModemPppoeAndDisconnectedSessions()
    {
        var api = new FakeRas
        {
            Connections = [Connection(1, "vpn"), Connection(2, "modem"), Connection(3, "PPPoE"), Connection(4, "vpn")]
        };
        api.States[4] = new(0, 0x2001, 0);
        using var provider = Provider(api);
        Assert.Equal((nint)1, Assert.Single(await provider.GetActiveVpnSessionsAsync(default)).Handle);
        Assert.Empty(api.HungUp);
    }

    [Fact] public async Task RasIgnoresConnectionsThatDisappearDuringEnumeration()
    {
        var api = new FakeRas { Connections = [Connection(1)] };
        api.States[1] = new(6, 0, 0);
        using var provider = Provider(api);
        Assert.Empty(await provider.GetActiveVpnSessionsAsync(default));
    }

    [Fact] public async Task RasStatusFailureNeverDisconnects()
    {
        var api = new FakeRas { Connections = [Connection(1)] };
        api.States[1] = new(5, 0, 0);
        using var provider = Provider(api);
        await Assert.ThrowsAsync<Win32Exception>(() => provider.GetActiveVpnSessionsAsync(default));
        Assert.Empty(api.HungUp);
    }

    [Fact] public async Task RasDisconnectUsesVerifiedHandleAndConfirmsCleanup()
    {
        var api = new FakeRas { Connections = [Connection(1)] };
        using var provider = Provider(api);
        var session = Assert.Single(await provider.GetActiveVpnSessionsAsync(default));
        Assert.Equal(DisconnectResult.Disconnected, await provider.DisconnectVpnSessionAsync(session, default));
        Assert.Equal((nint)1, Assert.Single(api.HungUp));
    }

    [Fact] public async Task RasRecycledHandleCannotDisconnectDifferentConnection()
    {
        var api = new FakeRas { Connections = [Connection(1)] };
        using var provider = Provider(api);
        var session = Assert.Single(await provider.GetActiveVpnSessionsAsync(default));
        api.Connections = [Connection(1) with { CorrelationId = Guid.NewGuid() }];
        Assert.Equal(DisconnectResult.AlreadyGone, await provider.DisconnectVpnSessionAsync(session, default));
        Assert.Empty(api.HungUp);
    }

    [Fact] public async Task RasProviderItselfRefusesTestModeDisconnect()
    {
        var api = new FakeRas { Connections = [Connection(1)] };
        using var provider = Provider(api, true);
        var session = Assert.Single(await provider.GetActiveVpnSessionsAsync(default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.DisconnectVpnSessionAsync(session, default));
        Assert.Empty(api.HungUp);
    }

    [Fact] public async Task RasHangupFailureIsSurfaced()
    {
        var api = new FakeRas { Connections = [Connection(1)], HangupError = 5 };
        using var provider = Provider(api);
        var session = Assert.Single(await provider.GetActiveVpnSessionsAsync(default));
        await Assert.ThrowsAsync<Win32Exception>(() => provider.DisconnectVpnSessionAsync(session, default));
    }

    private static WazuhRecoveryService Recovery(FakeService service) => new(service,
        new() { RestartAttempts = 3, RestartDelaySeconds = 1, RestartTimeoutSeconds = 1 },
        TimeProvider.System, NullLogger<WazuhRecoveryService>.Instance);
    private static RasConnection Connection(int handle, string deviceType = "vpn") =>
        new(handle, $"VPN {handle}", deviceType, "WAN Miniport (IKEv2)", Guid.NewGuid(), true);
    private static RasVpnSessionManager Provider(FakeRas api, bool testMode = false) => new(api,
        new() { TestMode = testMode }, TimeProvider.System, NullLogger<RasVpnSessionManager>.Instance);

    private sealed class FakeRas : IRasApi
    {
        public IReadOnlyList<RasConnection> Connections = [];
        public Dictionary<nint, RasStatus> States { get; } = [];
        public List<nint> HungUp { get; } = [];
        public uint HangupError;
        public IReadOnlyList<RasConnection> Enumerate() => Connections;
        public RasStatus GetStatus(nint handle) => HungUp.Contains(handle) && HangupError == 0
            ? new(6, 0, 0) : States.GetValueOrDefault(handle, new(0, NativeRasApi.Connected, 0));
        public uint HangUp(nint handle) { HungUp.Add(handle); return HangupError; }
    }
    private sealed class FakeService : IWazuhServiceControl
    {
        public WazuhServiceStatus Status;
        public bool StartWorks;
        public int Starts;
        public Exception? Error;
        public Action? OnStart;
        public WazuhServiceStatus GetStatus() { if (Error is not null) throw Error; return Status; }
        public void Start() { Starts++; OnStart?.Invoke(); if (StartWorks) Status = WazuhServiceStatus.Running; }
    }
    private sealed class FakeInstallation : IInstallationProbe
    {
        public bool Present = true;
        public bool Exists() => Present;
    }
}
