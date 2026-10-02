using Microsoft.Extensions.Logging.Abstractions;
using WazuhGuard.Core;

namespace WazuhGuard.Tests;

public sealed class GuardStateMachineTests
{
    [Fact] public async Task DetectionOnlyVendorSessionIsNeverEnforcedButRasContinues()
    {
        using var f = new Fixture();
        f.Vpn.Sessions = [Session("observation") with { DisconnectSupported = false }, Session("ras")];
        await f.EnterEnforcing();
        Assert.Equal("ras", Assert.Single(f.Vpn.Disconnected).Id);
    }
    [Fact] public async Task HealthyRemainsHealthy()
    {
        using var f = new Fixture();
        await f.Tick();
        Assert.Equal(GuardState.Healthy, f.Machine.State);
        Assert.Equal(0, f.Recovery.Calls);
        Assert.Equal(0, f.Vpn.DiscoveryCalls);
    }

    [Fact] public async Task StoppedRecoversAndRechecksInstallation()
    {
        using var f = new Fixture();
        f.Health.Status = HealthStatus.Stopped;
        f.Recovery.Action = () => { f.Health.Status = HealthStatus.Healthy; return true; };
        await f.Tick();
        Assert.Equal(1, f.Recovery.Calls);
        Assert.Equal(GuardState.Healthy, f.Machine.State);
        Assert.Equal(2, f.Health.Calls);
    }

    [Fact] public async Task RecoveryReturnValueIsNotTrustedWithoutHealthCheck()
    {
        using var f = new Fixture();
        f.Health.Status = HealthStatus.Stopped;
        f.Recovery.Action = () => true;
        await f.Tick();
        Assert.Equal(GuardState.GracePeriod, f.Machine.State);
    }

    [Theory]
    [InlineData(HealthStatus.Stopped, 1)]
    [InlineData(HealthStatus.ServiceMissing, 0)]
    [InlineData(HealthStatus.InstallationMissing, 0)]
    [InlineData(HealthStatus.Paused, 0)]
    [InlineData(HealthStatus.Pending, 0)]
    public async Task VerifiedFailureEntersGrace(HealthStatus status, int attempts)
    {
        using var f = new Fixture();
        f.Health.Status = status;
        await f.Tick();
        Assert.Equal(GuardState.GracePeriod, f.Machine.State);
        Assert.Equal(attempts, f.Recovery.Calls);
        Assert.Empty(f.Vpn.Disconnected);
    }

    [Fact] public async Task GraceRecoveryReturnsHealthy()
    {
        using var f = new Fixture();
        await f.EnterGrace();
        f.Health.Status = HealthStatus.Healthy;
        await f.Tick();
        Assert.Equal(GuardState.Healthy, f.Machine.State);
    }

    [Fact] public async Task GraceDeadlineIsInclusiveAndFinalCheckRequired()
    {
        using var f = new Fixture();
        await f.EnterGrace();
        f.Clock.Advance(119);
        await f.Tick();
        Assert.Equal(GuardState.GracePeriod, f.Machine.State);
        var before = f.Health.Calls;
        f.Clock.Advance(1);
        await f.Tick();
        Assert.Equal(before + 2, f.Health.Calls);
        Assert.Equal(GuardState.Enforcing, f.Machine.State);
        Assert.Equal(1, f.Vpn.DiscoveryCalls);
    }

    [Fact] public async Task FinalCheckHealthyPreventsEnforcement()
    {
        using var f = new Fixture();
        await f.EnterGrace();
        f.Clock.Advance(120);
        f.Health.Sequence.Enqueue(HealthStatus.ServiceMissing);
        f.Health.Sequence.Enqueue(HealthStatus.Healthy);
        await f.Tick();
        Assert.Equal(GuardState.Healthy, f.Machine.State);
        Assert.Equal(0, f.Vpn.DiscoveryCalls);
    }

    [Fact] public async Task EnforcingWithoutVpnContinuesMonitoring()
    {
        using var f = new Fixture();
        await f.EnterEnforcing();
        await f.Tick();
        Assert.Equal(GuardState.Enforcing, f.Machine.State);
        Assert.Equal(2, f.Vpn.DiscoveryCalls);
        Assert.Empty(f.Vpn.Disconnected);
    }

    [Fact] public async Task ProductionDisconnectsAllSessionsAndReconnections()
    {
        using var f = new Fixture();
        f.Vpn.Sessions = [Session("1"), Session("2")];
        await f.EnterEnforcing();
        Assert.Equal(2, f.Vpn.Disconnected.Count);
        f.Vpn.Sessions = [Session("3")];
        await f.Tick();
        Assert.Equal(new[] { "1", "2", "3" }, f.Vpn.Disconnected.Select(s => s.Id));
    }

    [Fact] public async Task WazuhRecoveryStopsInterference()
    {
        using var f = new Fixture();
        await f.EnterEnforcing();
        f.Health.Status = HealthStatus.Healthy;
        f.Vpn.Sessions = [Session("new")];
        await f.Tick();
        Assert.Equal(GuardState.Healthy, f.Machine.State);
        Assert.Empty(f.Vpn.Disconnected);
        Assert.Equal(1, f.Vpn.DiscoveryCalls);
    }

    [Fact] public async Task TestModeDiscoversButNeverDisconnects()
    {
        using var f = new Fixture(testMode: true);
        f.Vpn.Sessions = [Session("1")];
        await f.EnterEnforcing();
        await f.Tick();
        Assert.Equal(2, f.Vpn.DiscoveryCalls);
        Assert.Empty(f.Vpn.Disconnected);
    }

    [Fact] public async Task MonitoringExceptionCannotEnterEnforcing()
    {
        using var f = new Fixture();
        f.Health.Error = new IOException("SCM inaccessible");
        await f.Tick();
        f.Clock.Advance(1000);
        await f.Tick();
        Assert.NotEqual(GuardState.Enforcing, f.Machine.State);
        Assert.Equal(0, f.Vpn.DiscoveryCalls);
    }

    [Fact] public async Task UnknownDuringEnforcementRequiresFreshGrace()
    {
        using var f = new Fixture();
        await f.EnterEnforcing();
        f.Health.Error = new UnauthorizedAccessException();
        await f.Tick();
        f.Clock.Advance(1000);
        f.Health.Error = null;
        await f.Tick();
        Assert.Equal(GuardState.GracePeriod, f.Machine.State);
        Assert.Equal(1, f.Vpn.DiscoveryCalls);
        f.Clock.Advance(120);
        await f.Tick();
        Assert.Equal(GuardState.Enforcing, f.Machine.State);
    }

    [Fact] public async Task UnknownFinalCheckDoesNotEnforce()
    {
        using var f = new Fixture();
        await f.EnterGrace();
        f.Clock.Advance(120);
        f.Health.Sequence.Enqueue(HealthStatus.ServiceMissing);
        f.Health.Sequence.Enqueue(HealthStatus.Unknown);
        await f.Tick();
        Assert.Equal(GuardState.GracePeriod, f.Machine.State);
        Assert.Equal(0, f.Vpn.DiscoveryCalls);
    }

    [Fact] public async Task RecoveryBetweenDiscoveryAndDisconnectPreventsDisconnect()
    {
        using var f = new Fixture();
        f.Vpn.Sessions = [Session("1")];
        f.Vpn.OnDiscovery = () => f.Health.Status = HealthStatus.Healthy;
        await f.EnterEnforcing();
        Assert.Equal(GuardState.Healthy, f.Machine.State);
        Assert.Empty(f.Vpn.Disconnected);
    }

    [Fact] public async Task HealthCheckedBetweenEveryDisconnect()
    {
        using var f = new Fixture();
        f.Vpn.Sessions = [Session("1"), Session("2")];
        f.Vpn.OnDisconnect = () => f.Health.Status = HealthStatus.Healthy;
        await f.EnterEnforcing();
        Assert.Single(f.Vpn.Disconnected);
        Assert.Equal(GuardState.Healthy, f.Machine.State);
    }

    [Fact] public async Task VpnEnumerationErrorRetriesNextTick()
    {
        using var f = new Fixture();
        f.Vpn.DiscoveryError = new IOException("RAS unavailable");
        await f.EnterEnforcing();
        f.Vpn.DiscoveryError = null;
        f.Vpn.Sessions = [Session("1")];
        await f.Tick();
        Assert.Single(f.Vpn.Disconnected);
    }

    [Fact] public async Task OneDisconnectFailureDoesNotSkipOtherSessions()
    {
        using var f = new Fixture();
        f.Vpn.Sessions = [Session("1"), Session("2")];
        f.Vpn.FailId = "1";
        await f.EnterEnforcing();
        Assert.Equal("2", Assert.Single(f.Vpn.Disconnected).Id);
    }

    [Fact] public async Task CancelledTickDoesNoWork()
    {
        using var f = new Fixture();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Machine.TickAsync(new CancellationToken(true)));
        Assert.Equal(0, f.Health.Calls);
    }

    [Fact] public async Task ConcurrentTicksCannotOverlapRecovery()
    {
        using var f = new Fixture();
        f.Health.Status = HealthStatus.Stopped;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Recovery.AsyncAction = async () => { entered.SetResult(); return await release.Task; };
        var first = f.Tick();
        await entered.Task;
        var second = f.Tick();
        Assert.False(second.IsCompleted);
        Assert.Equal(1, f.Recovery.Calls);
        release.SetResult(false);
        await Task.WhenAll(first, second);
        Assert.Equal(1, f.Recovery.Calls);
    }

    [Fact] public async Task DisabledRecoveryEntersGraceWithoutStart()
    {
        using var f = new Fixture(restartAttempts: 0);
        f.Health.Status = HealthStatus.Stopped;
        await f.Tick();
        Assert.Equal(GuardState.GracePeriod, f.Machine.State);
        Assert.Equal(0, f.Recovery.Calls);
    }

    internal static VpnSession Session(string id) => new("fake", id, "Lab VPN", "Connected", "Fake", 1, Guid.Empty, true);
    private sealed class Fixture : IDisposable
    {
        public readonly FakeClock Clock = new();
        public readonly FakeHealth Health = new();
        public readonly FakeRecovery Recovery = new();
        public readonly FakeVpn Vpn = new();
        public GuardStateMachine Machine { get; }
        public Fixture(bool testMode = false, int restartAttempts = 3) => Machine = new(Health, Recovery, Vpn,
            new() { TestMode = testMode, RestartAttempts = restartAttempts }, Clock, NullLogger<GuardStateMachine>.Instance);
        public Task Tick() => Machine.TickAsync(CancellationToken.None);
        public async Task EnterGrace() { Health.Status = HealthStatus.ServiceMissing; await Tick(); }
        public async Task EnterEnforcing() { await EnterGrace(); Clock.Advance(120); await Tick(); }
        public void Dispose() => Machine.Dispose();
    }
}

internal sealed class FakeClock : TimeProvider
{
    private long timestamp;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => timestamp;
    public void Advance(int seconds) => timestamp += TimeSpan.FromSeconds(seconds).Ticks;
}
internal sealed class FakeHealth : IWazuhHealthMonitor
{
    public HealthStatus Status = HealthStatus.Healthy;
    public Exception? Error;
    public int Calls;
    public Queue<HealthStatus> Sequence { get; } = [];
    public Task<HealthSnapshot> CheckAsync(CancellationToken ct)
    {
        Calls++;
        if (Error is not null) throw Error;
        return Task.FromResult(new HealthSnapshot(Sequence.Count > 0 ? Sequence.Dequeue() : Status, "test observation"));
    }
}
internal sealed class FakeRecovery : IWazuhRecoveryService
{
    public int Calls;
    public Func<bool> Action = () => false;
    public Func<Task<bool>>? AsyncAction;
    public Task<bool> TryRecoverAsync(CancellationToken ct) { Calls++; return AsyncAction?.Invoke() ?? Task.FromResult(Action()); }
}
internal sealed class FakeVpn : IVpnSessionManager
{
    public IReadOnlyList<VpnSession> Sessions = [];
    public List<VpnSession> Disconnected { get; } = [];
    public int DiscoveryCalls;
    public Exception? DiscoveryError;
    public string? FailId;
    public Action? OnDiscovery, OnDisconnect;
    public Task<IReadOnlyList<VpnSession>> GetActiveVpnSessionsAsync(CancellationToken ct)
    {
        DiscoveryCalls++;
        if (DiscoveryError is not null) throw DiscoveryError;
        OnDiscovery?.Invoke();
        return Task.FromResult(Sessions);
    }
    public Task<DisconnectResult> DisconnectVpnSessionAsync(VpnSession session, CancellationToken ct)
    {
        if (session.Id == FailId) throw new IOException("fake disconnect error");
        Disconnected.Add(session);
        OnDisconnect?.Invoke();
        return Task.FromResult(DisconnectResult.Disconnected);
    }
}
