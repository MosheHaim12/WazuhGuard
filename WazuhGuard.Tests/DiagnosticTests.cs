using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WazuhGuard.Core;
using WazuhGuard.Diagnostics;
using WazuhGuard.Monitoring;
using WazuhGuard.Recovery;
using WazuhGuard.Vpn;

namespace WazuhGuard.Tests;

public sealed class DiagnosticTests
{
    [Theory]
    [InlineData("--check-wazuh", DiagnosticOperation.CheckWazuh)]
    [InlineData("--list-vpn", DiagnosticOperation.ListVpn)]
    [InlineData("--disconnect-vpn", DiagnosticOperation.DisconnectVpn)]
    [InlineData("--check-and-repair-wazuh", DiagnosticOperation.CheckAndRepairWazuh)]
    [InlineData("--help", DiagnosticOperation.Help)]
    public void CommandsDispatchExactly(string flag, DiagnosticOperation operation) =>
        Assert.Equal(operation, DiagnosticCommand.Parse([flag]).Operation);

    [Fact] public void IdentifierIsPreserved() => Assert.Equal("Lab VPN", DiagnosticCommand.Parse(["--disconnect-vpn", "Lab VPN"]).Identifier);

    public static TheoryData<string[]> InvalidCommands => new()
    {
        Array.Empty<string>(), new[] { "--unknown" }, new[] { "--list-vpn", "--disconnect-vpn" }, new[] { "--disconnect-vpn", "" },
        new[] { "--disconnect-vpn", "--force" }, new[] { "--disconnect-vpn", "one", "two" }, new[] { "--check-and-repair-wazuh", "extra" }
    };
    [Theory]
    [MemberData(nameof(InvalidCommands))]
    public void InvalidCommandsCannotFallThroughToAnotherOperation(string[] args) => Assert.Throws<ArgumentException>(() => DiagnosticCommand.Parse(args));

    [Fact] public void BothEntrypointsShareProductionRegistrationsWithoutAutomaticWorker()
    {
        var services = new ServiceCollection().AddLogging().AddWazuhGuardPrimitives(new());
        using var provider = services.BuildServiceProvider();
        Assert.IsType<WazuhHealthMonitor>(provider.GetRequiredService<IWazuhHealthMonitor>());
        Assert.IsType<WindowsWazuhService>(provider.GetRequiredService<IWazuhServiceControl>());
        Assert.IsType<WazuhRecoveryService>(provider.GetRequiredService<IWazuhRecoveryService>());
        Assert.IsType<CompositeVpnSessionManager>(provider.GetRequiredService<IVpnSessionManager>());
        Assert.Equal(new[] { "WindowsRAS", "CheckPoint", "FortiClient" }, provider.GetServices<IVpnProvider>().Select(p => p.Id));
        Assert.IsType<NativeRasApi>(provider.GetRequiredService<IRasApi>());
        Assert.Empty(provider.GetServices<IHostedService>());
        Assert.Null(provider.GetService<IGuardStateMachine>());
        // Only inspect registrations. No method above calls a native API.
    }

    [Theory]
    [InlineData(HealthStatus.Healthy, 0, "Healthy")]
    [InlineData(HealthStatus.Stopped, 1, "Unhealthy")]
    [InlineData(HealthStatus.ServiceMissing, 1, "Unhealthy")]
    [InlineData(HealthStatus.InstallationMissing, 1, "Unhealthy")]
    [InlineData(HealthStatus.Unknown, 3, "Unknown")]
    public async Task HealthIsReadOnlyAndHasCorrectExitCode(HealthStatus status, int code, string label)
    {
        var f = new Fixture(); f.Health.Status = status;
        Assert.Equal(code, await f.Run("--check-wazuh"));
        Assert.Contains($"Overall health: {label}", f.Output.ToString());
        Assert.Equal(0, f.Recovery.Calls);
        Assert.Equal(0, f.Vpn.Discoveries);
        Assert.Empty(f.Vpn.Requests);
    }

    [Fact] public async Task HealthExceptionPrintsUnknownWithOriginalErrorAndNeverRepairs()
    {
        var f = new Fixture(); f.Health.Error = new IOException("lab SCM failure");
        Assert.Equal(3, await f.Run("--check-and-repair-wazuh"));
        Assert.Contains("Overall health: Unknown", f.Output.ToString());
        Assert.Contains("lab SCM failure", f.Output.ToString());
        Assert.Equal(0, f.Recovery.Calls);
    }

    [Fact] public async Task PartialHealthExceptionPrintsKnownFacts()
    {
        var f = new Fixture();
        f.Health.Error = new HealthCheckException(new(HealthStatus.Unknown, "directory access failure")
        { Diagnostics = new(true, "Stopped", null, false) }, new UnauthorizedAccessException("denied"));
        Assert.Equal(3, await f.Run("--check-wazuh"));
        Assert.Contains("Windows service state: Stopped", f.Output.ToString());
        Assert.Contains("Service exists: Yes", f.Output.ToString());
        Assert.Contains("Overall health: Unknown", f.Output.ToString());
    }

    [Fact] public async Task ListingEmptyVpnSetIsExplicitAndReadOnly()
    {
        var f = new Fixture();
        Assert.Equal(0, await f.Run("--list-vpn"));
        Assert.Contains("No supported VPN sessions were detected", f.Output.ToString());
        Assert.Empty(f.Vpn.Requests);
        Assert.Equal(0, f.Health.Calls);
    }

    [Fact] public async Task ListingPrintsProductionMetadata()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")];
        Assert.Equal(0, await f.Run("--list-vpn"));
        Assert.Contains("Device type: vpn", f.Output.ToString());
        Assert.Contains("Device", f.Output.ToString());
        Assert.Contains("192.0.2.2", f.Output.ToString());
        Assert.Contains("198.51.100.1", f.Output.ToString());
        Assert.Contains("Session ID: a", f.Output.ToString());
        Assert.Empty(f.Vpn.Requests);
    }

    [Fact] public async Task SingleSessionDisconnectPrintsSelectionBeforeCallingProductionPrimitive()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")];
        f.Vpn.BeforeDisconnect = () => Assert.Contains("Selected session for disconnection:", f.Output.ToString());
        Assert.Equal(0, await f.Run("--disconnect-vpn"));
        Assert.Equal("a", Assert.Single(f.Vpn.Requests).Id);
        Assert.Equal(2, f.Vpn.Discoveries);
        Assert.Contains("PASS: selected session is absent", f.Output.ToString());
        Assert.Equal(0, f.Health.Calls);
    }

    [Fact] public async Task MultipleSessionsRequireIdentifier()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a"), Session("b")];
        Assert.Equal(2, await f.Run("--disconnect-vpn"));
        Assert.Empty(f.Vpn.Requests);
    }

    [Theory]
    [InlineData("b")]
    [InlineData("Second VPN")]
    public async Task IdentifierSelectsOnlyOneSession(string identifier)
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a"), Session("b") with { Name = "Second VPN" }];
        Assert.Equal(0, await f.Run("--disconnect-vpn", identifier));
        Assert.Equal("b", Assert.Single(f.Vpn.Requests).Id);
        Assert.Equal("a", Assert.Single(f.Vpn.Sessions).Id);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("Lab VPN")]
    public async Task MissingOrAmbiguousNameCannotDisconnectAnything(string identifier)
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a"), Session("b")];
        Assert.Equal(2, await f.Run("--disconnect-vpn", identifier));
        Assert.Empty(f.Vpn.Requests);
    }

    [Fact] public async Task NoVpnToDisconnectIsNonzero()
    {
        var f = new Fixture();
        Assert.Equal(2, await f.Run("--disconnect-vpn"));
        Assert.Empty(f.Vpn.Requests);
    }

    [Fact] public async Task TestModeCannotBeBypassedByManualCommand()
    {
        var f = new Fixture(testMode: true); f.Vpn.Sessions = [Session("a")];
        Assert.Equal(4, await f.Run("--disconnect-vpn"));
        Assert.Empty(f.Vpn.Requests);
        Assert.Contains("TestMode=true", f.Output.ToString());
    }

    [Fact] public async Task DetectionOnlySessionCannotBeDisconnectedManually()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a") with { DisconnectSupported = false }];
        Assert.Equal(4, await f.Run("--disconnect-vpn"));
        Assert.Empty(f.Vpn.Requests);
    }

    [Fact] public async Task OwningProviderErrorDuringVerificationCannotReportPass()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")];
        f.Vpn.AfterDisconnect = () => f.Vpn.ProviderState = VpnProviderState.Error;
        Assert.Equal(3, await f.Run("--disconnect-vpn"));
        Assert.DoesNotContain("PASS:", f.Output.ToString());
    }

    [Fact] public async Task ListPreservesUsefulEvidenceButExitsNonzeroOnProviderError()
    {
        var f = new Fixture(); f.Vpn.ProviderState = VpnProviderState.Error;
        Assert.Equal(3, await f.Run("--list-vpn"));
        Assert.Contains("Provider: WindowsRAS; result: Error", f.Output.ToString());
        Assert.Empty(f.Vpn.Requests);
    }

    [Fact] public async Task SuccessfulApiReturnIsNotEnoughIfSessionRemains()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")]; f.Vpn.RemoveOnDisconnect = false;
        Assert.Equal(5, await f.Run("--disconnect-vpn"));
        Assert.Contains("FAIL: selected session is still", f.Output.ToString());
    }

    [Fact] public async Task ReconnectionIsReportedButNeverDisconnectedAgain()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")];
        f.Vpn.AfterDisconnect = () => f.Vpn.Sessions = [Session("b")];
        Assert.Equal(0, await f.Run("--disconnect-vpn"));
        Assert.Single(f.Vpn.Requests);
        Assert.Contains("possible automatic reconnection", f.Output.ToString());
    }

    [Fact] public async Task DisconnectFailureStillReenumeratesAndNeverReportsPass()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")];
        f.Vpn.AfterDisconnect = () => throw new IOException("hangup failed");
        Assert.Equal(3, await f.Run("--disconnect-vpn"));
        Assert.Equal(2, f.Vpn.Discoveries);
        Assert.Contains("hangup failed", f.Output.ToString());
        Assert.DoesNotContain("PASS:", f.Output.ToString());
    }

    [Fact] public async Task DiscoveryFailureCannotReportNoVpnOrDisconnect()
    {
        var f = new Fixture(); f.Vpn.DiscoveryError = new IOException("RAS unavailable");
        Assert.Equal(3, await f.Run("--list-vpn"));
        Assert.Empty(f.Vpn.Requests);
        Assert.DoesNotContain("No supported VPN", f.Output.ToString());
    }

    [Fact] public async Task VerificationFailureCannotReportPass()
    {
        var f = new Fixture(); f.Vpn.Sessions = [Session("a")];
        f.Vpn.AfterDisconnect = () => f.Vpn.DiscoveryError = new IOException("verification unavailable");
        Assert.Equal(3, await f.Run("--disconnect-vpn"));
        Assert.DoesNotContain("PASS:", f.Output.ToString());
    }

    [Theory]
    [InlineData(HealthStatus.Healthy, 0)]
    [InlineData(HealthStatus.ServiceMissing, 1)]
    [InlineData(HealthStatus.InstallationMissing, 1)]
    [InlineData(HealthStatus.Pending, 1)]
    [InlineData(HealthStatus.Paused, 1)]
    [InlineData(HealthStatus.Unknown, 3)]
    public async Task RepairIsOnlyRequestedForVerifiedStoppedService(HealthStatus status, int exit)
    {
        var f = new Fixture(); f.Health.Status = status;
        Assert.Equal(exit, await f.Run("--check-and-repair-wazuh"));
        Assert.Equal(0, f.Recovery.Calls);
        Assert.Equal(0, f.Vpn.Discoveries);
    }

    [Fact] public async Task RepairUsesExistingPrimitiveAndRechecks()
    {
        var f = new Fixture(testMode: true); f.Health.Status = HealthStatus.Stopped;
        f.Recovery.Action = () => { f.Health.Status = HealthStatus.Healthy; return true; };
        Assert.Equal(0, await f.Run("--check-and-repair-wazuh"));
        Assert.Equal(1, f.Recovery.Calls);
        Assert.Equal(2, f.Health.Calls);
        Assert.Equal(0, f.Vpn.Discoveries);
    }

    [Fact] public async Task RepairReturnValueCannotReplacePostRecoveryHealthCheck()
    {
        var f = new Fixture(); f.Health.Status = HealthStatus.Stopped; f.Recovery.Action = () => true;
        Assert.Equal(1, await f.Run("--check-and-repair-wazuh"));
        Assert.Equal(2, f.Health.Calls);
        Assert.Contains("FAIL: recovery", f.Output.ToString());
    }

    [Fact] public async Task RepairExceptionStillRechecksHealthAndReportsError()
    {
        var f = new Fixture(); f.Health.Status = HealthStatus.Stopped;
        f.Recovery.Action = () => throw new IOException("repair failure");
        Assert.Equal(3, await f.Run("--check-and-repair-wazuh"));
        Assert.Equal(2, f.Health.Calls);
        Assert.Contains("repair failure", f.Output.ToString());
    }

    [Fact] public async Task CancellationDoesNotPerformWork()
    {
        var f = new Fixture();
        Assert.Equal(130, await f.Runner.RunAsync(new(DiagnosticOperation.DisconnectVpn), new CancellationToken(true)));
        Assert.Equal(0, f.Vpn.Discoveries);
    }

    private static VpnSession Session(string id) => new("WindowsRAS", id, "Lab VPN", "Connected", "RAS", 1, Guid.NewGuid(), false)
    { DeviceType = "vpn", DeviceName = "Device", LocalTunnelEndpoint = "192.0.2.2", RemoteTunnelEndpoint = "198.51.100.1" };
    private sealed class Fixture
    {
        public readonly StringWriter Output = new();
        public readonly FakeHealth Health = new();
        public readonly FakeRecovery Recovery = new();
        public readonly ManualFakeVpn Vpn = new();
        public DiagnosticRunner Runner { get; }
        public Fixture(bool testMode = false) => Runner = new(Health, Recovery, Vpn, new() { TestMode = testMode }, Output);
        public Task<int> Run(params string[] args) => Runner.RunAsync(DiagnosticCommand.Parse(args), default);
    }
    private sealed class ManualFakeVpn : IVpnSessionManager
    {
        public IReadOnlyList<VpnSession> Sessions = [];
        public List<VpnSession> Requests { get; } = [];
        public int Discoveries;
        public bool RemoveOnDisconnect = true;
        public Action? BeforeDisconnect, AfterDisconnect;
        public Exception? DiscoveryError;
        public VpnProviderState ProviderState = VpnProviderState.Available;
        public async Task<VpnDiscoveryReport> DiscoverAsync(CancellationToken ct)
        {
            var sessions = await GetActiveVpnSessionsAsync(ct);
            return new(sessions, [new("WindowsRAS", new(true, true, true, "fake"), ProviderState, "test", sessions)], []);
        }
        public Task<IReadOnlyList<VpnSession>> GetActiveVpnSessionsAsync(CancellationToken ct)
        {
            Discoveries++;
            if (DiscoveryError is not null) throw DiscoveryError;
            return Task.FromResult(Sessions);
        }
        public Task<DisconnectResult> DisconnectVpnSessionAsync(VpnSession session, CancellationToken ct)
        {
            BeforeDisconnect?.Invoke(); Requests.Add(session);
            if (RemoveOnDisconnect) Sessions = Sessions.Where(s => s.Id != session.Id).ToArray();
            AfterDisconnect?.Invoke();
            return Task.FromResult(DisconnectResult.Disconnected);
        }
    }
}
