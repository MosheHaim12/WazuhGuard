using Microsoft.Extensions.Logging.Abstractions;
using WazuhGuard.Core;
using WazuhGuard.Vpn;

namespace WazuhGuard.Tests;

public sealed class VpnProviderTests
{
    [Fact] public async Task CompositePreservesOtherProvidersWhenOneFailsAndKeepsEvidenceSeparate()
    {
        var ras = new FakeProvider("WindowsRAS"); var cp = new FakeProvider("CheckPoint") { Error = new IOException("unavailable") };
        using var manager = Composite([ras, cp]);
        var report = await manager.DiscoverAsync(default);
        Assert.Equal("WindowsRAS", Assert.Single(report.Sessions).Provider);
        Assert.Equal(VpnProviderState.Error, report.Providers[1].State);
        Assert.Single(report.Evidence);
        Assert.DoesNotContain(report.Sessions, s => s.Provider == "Unsupported/Unknown");
    }

    [Fact] public async Task CompositeRoutesOnlyToTheOwningProvider()
    {
        var ras = new FakeProvider("WindowsRAS"); var forti = new FakeProvider("FortiClient");
        using var manager = Composite([ras, forti]);
        var session = (await manager.GetActiveVpnSessionsAsync(default)).Single(s => s.Provider == "FortiClient");
        await manager.DisconnectVpnSessionAsync(session, default);
        Assert.Equal(0, ras.Disconnects); Assert.Equal(1, forti.Disconnects);
    }

    [Fact] public async Task CompositeRefusesUnknownAndDetectionOnlySessions()
    {
        var vendor = new FakeProvider("ReadOnly") { AllowDisconnect = false };
        using var manager = Composite([vendor]);
        await Assert.ThrowsAsync<NotSupportedException>(() => manager.DisconnectVpnSessionAsync(Session("Unregistered"), default));
        await Assert.ThrowsAsync<NotSupportedException>(() => manager.DisconnectVpnSessionAsync(Session("ReadOnly"), default));
        Assert.Equal(0, vendor.Disconnects);
    }

    [Fact] public async Task CompositeTestModeIsEnforcedEvenIfProviderWouldAllowDisconnect()
    {
        var vendor = new FakeProvider("test");
        using var manager = Composite([vendor], true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.DisconnectVpnSessionAsync(Session("test"), default));
        Assert.Equal(0, vendor.Disconnects);
    }

    [Fact] public async Task ProviderCannotClaimOwnershipOfAnotherProvidersSession()
    {
        var vendor = new FakeProvider("test") { SessionProvider = "WindowsRAS" };
        using var manager = Composite([vendor]);
        var report = await manager.DiscoverAsync(default);
        Assert.Empty(report.Sessions); Assert.Equal(VpnProviderState.Error, report.Providers[0].State);
    }

    [Fact] public async Task CheckPointParsesVerifiedActiveSiteAndUsesDocumentedDisconnect()
    {
        const string connected = "Trac connections:\n\nConn TC office:\n    gw: 82.80.134.62\n    status: Connected\n    active site: true\n";
        const string disconnected = "Trac connections:\n";
        var runner = new FakeRunner();
        runner.Results.Enqueue(new(0, connected, "")); // discover
        runner.Results.Enqueue(new(0, connected, "")); // pre-disconnect revalidation
        runner.Results.Enqueue(new(0, "", "")); // trac disconnect
        runner.Results.Enqueue(new(0, disconnected, "")); // verification
        var provider = new CheckPointVpnProvider(new FakeLocator(), runner, new() { TestMode = false }, TimeProvider.System);
        var report = await provider.DiscoverAsync(default);
        var session = Assert.Single(report.Sessions);
        Assert.Equal("TC office", session.Name);
        Assert.Equal("82.80.134.62", session.RemoteTunnelEndpoint);
        Assert.True(session.DisconnectSupported);
        Assert.Equal(DisconnectResult.Disconnected, await provider.DisconnectAsync(session, default));
        Assert.Equal(new[] { "disconnect" }, runner.Commands[2]);
    }

    [Fact] public void CheckPointParserIgnoresDisconnectedAndInactiveSites()
    {
        const string info = "Conn old:\n gw: old-gw\n status: Disconnected\n active site: false\nConn current:\n gw: 10.0.0.1\n status: Connected\n active site: true\n";
        var site = Assert.Single(CheckPointVpnProvider.ParseConnectedSites(info));
        Assert.Equal("current", site.Name); Assert.Equal("10.0.0.1", site.Gateway);
    }

    [Fact] public async Task MissingVendorBinaryIsReportedWithoutRunningCommands()
    {
        var runner = new FakeRunner();
        var report = await new CheckPointVpnProvider(new FakeLocator { Missing = true }, runner, new(), TimeProvider.System).DiscoverAsync(default);
        Assert.Equal(VpnProviderState.NotInstalled, report.State); Assert.Empty(runner.Commands);
    }

    [Theory]
    [InlineData(1, false, "error")]
    [InlineData(0, true, "")]
    [InlineData(0, false, "error")]
    public async Task CheckPointNonzeroOrTruncatedOutputIsUnknownNotDisconnected(int exitCode, bool truncated, string error)
    {
        var runner = new FakeRunner(); runner.Results.Enqueue(new(exitCode, "", error, truncated));
        var report = await new CheckPointVpnProvider(new FakeLocator(), runner, new(), TimeProvider.System).DiscoverAsync(default);
        Assert.Equal(VpnProviderState.Error, report.State); Assert.Empty(report.Sessions);
    }

    [Fact] public async Task FortiStatusDetectsOnlyConnectedProfilesAndDefaultsToDetectionOnly()
    {
        var runner = new FakeRunner(); runner.Results.Enqueue(new(0, "first :: Disconnected\nsecond :: Connected\nthird :: Connecting", ""));
        var report = await Forti(runner).DiscoverAsync(default);
        Assert.Equal("second", Assert.Single(report.Sessions).Name);
        Assert.False(report.Sessions[0].DisconnectSupported);
        Assert.Equal(new[] { "--cli", "--status" }, Assert.Single(runner.Commands));
    }

    [Theory]
    [InlineData("")]
    [InlineData("There are no connections")]
    [InlineData("a :: Connected\na :: Connected")]
    [InlineData("a :: Connected\nA :: Disconnected")]
    [InlineData("a :: Connected\nUnrecognized trailing text")]
    [InlineData("--all :: Connected")]
    [InlineData("a :: Verbunden")]
    public void FortiUnknownOrAmbiguousFormatCannotAuthorizeDisconnect(string output) =>
        Assert.Throws<InvalidDataException>(() => FortiClientVpnProvider.ParseStatus(output));

    [Fact] public async Task FortiUnrecognizedVersionDoesNotExecuteTheUtility()
    {
        var runner = new FakeRunner();
        var provider = new FortiClientVpnProvider(new FakeLocator { Version = new(7, 2, 0) }, runner, new(), TimeProvider.System);
        Assert.Equal(VpnProviderState.Unsupported, (await provider.DiscoverAsync(default)).State);
        Assert.Empty(runner.Commands);
    }

    [Fact] public async Task FortiDisconnectAlwaysTargetsOneProfileWithArgumentListNotShellText()
    {
        var runner = new FakeRunner();
        runner.Results.Enqueue(new(0, "Lab VPN & literal :: Connected\nother :: Connected", "")); // discover
        runner.Results.Enqueue(new(0, "Lab VPN & literal :: Connected\nother :: Connected", "")); // revalidate
        runner.Results.Enqueue(new(0, "", "")); // disconnect
        runner.Results.Enqueue(new(0, "Lab VPN & literal :: Disconnected\nother :: Connected", "")); // verify
        var provider = Forti(runner, enabled: true);
        var session = (await provider.DiscoverAsync(default)).Sessions[0];
        Assert.Equal(DisconnectResult.Disconnected, await provider.DisconnectAsync(session, default));
        Assert.Equal(new[] { "--cli", "--disconnect", "--tunnel", "Lab VPN & literal" }, runner.Commands[2]);
        Assert.Equal(4, runner.Commands.Count);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task FortiDisconnectHonorsBothSafetyGates(bool testMode, bool enabled)
    {
        var runner = new FakeRunner(); var provider = Forti(runner, enabled, testMode);
        await Assert.ThrowsAnyAsync<Exception>(() => provider.DisconnectAsync(Session("FortiClient"), default));
        Assert.Empty(runner.Commands);
    }

    [Fact] public async Task FortiNonzeroExitCannotProduceConnectedSessions()
    {
        var runner = new FakeRunner(); runner.Results.Enqueue(new(1, "a :: Connected", "access denied"));
        var report = await Forti(runner).DiscoverAsync(default);
        Assert.Equal(VpnProviderState.Error, report.State); Assert.Empty(report.Sessions);
    }

    [Fact] public async Task FortiRevalidationUnknownPreventsDisconnect()
    {
        var runner = new FakeRunner(); runner.Results.Enqueue(new(0, "a :: Connected", "")); runner.Results.Enqueue(new(0, "unknown", ""));
        var provider = Forti(runner, enabled: true); var session = Assert.Single((await provider.DiscoverAsync(default)).Sessions);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.DisconnectAsync(session, default));
        Assert.DoesNotContain(runner.Commands, c => c.Contains("--disconnect"));
    }

    [Theory]
    [InlineData("Check Point Virtual Network Adapter", "CheckPoint")]
    [InlineData("TracSrvWrapper", "CheckPoint")]
    [InlineData("Fortinet SSL VPN Virtual Ethernet Adapter", "FortiClient")]
    [InlineData("WireGuard Tunnel", "Unsupported/Unknown")]
    [InlineData("Ordinary Ethernet", null)]
    public void InventoryClassificationIsOnlyEvidence(string input, string? expected) => Assert.Equal(expected, WindowsVpnEnvironmentProbe.Classify(input));

    private static FortiClientVpnProvider Forti(FakeRunner runner, bool enabled = false, bool testMode = false) =>
        new(new FakeLocator(), runner, new() { TestMode = testMode, EnableFortiClientDisconnect = enabled }, TimeProvider.System);
    private static VpnSession Session(string provider) => new(provider, "one", "Lab VPN", "Connected", "fake", 1, Guid.Empty, false);
    private static CompositeVpnSessionManager Composite(IVpnProvider[] providers, bool testMode = false) =>
        new(providers, new FakeEnvironment(), new() { TestMode = testMode }, NullLogger<CompositeVpnSessionManager>.Instance);
    private sealed class FakeLocator : IVendorClientLocator
    {
        public bool Missing;
        public Version Version = new(7, 4, 7);
        public VendorClient? Find(string vendor) => Missing ? null : new(@"C:\Fake\Vendor.exe", Version, "test", vendor);
    }
    private sealed class FakeRunner : IVendorCommandRunner
    {
        public Queue<VendorCommandResult> Results { get; } = [];
        public List<string[]> Commands { get; } = [];
        public Task<VendorCommandResult> RunAsync(VendorClient client, IReadOnlyList<string> arguments, CancellationToken ct)
        { Commands.Add(arguments.ToArray()); return Task.FromResult(Results.Dequeue()); }
    }
    private sealed class FakeEnvironment : IVpnEnvironmentProbe
    {
        public IReadOnlyList<VpnEvidence> Inspect(CancellationToken ct) => [new("Unsupported/Unknown", "Adapter", "Example VPN adapter", "Up", "Not proof of connection")];
    }
    private sealed class FakeProvider(string id) : IVpnProvider
    {
        public string Id => id;
        public bool AllowDisconnect = true;
        public string? SessionProvider;
        public int Disconnects;
        public Exception? Error;
        public VpnCapabilities Capabilities => new(true, true, AllowDisconnect, "fake");
        public Task<VpnProviderReport> DiscoverAsync(CancellationToken ct)
        {
            if (Error is not null) throw Error;
            return Task.FromResult(new VpnProviderReport(Id, Capabilities, VpnProviderState.Available, "test", [Session(SessionProvider ?? Id)]));
        }
        public Task<DisconnectResult> DisconnectAsync(VpnSession session, CancellationToken ct) { Disconnects++; return Task.FromResult(DisconnectResult.Disconnected); }
    }
}
