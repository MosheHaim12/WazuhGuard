namespace WazuhGuard.Core;

public enum GuardState { Healthy, Recovering, GracePeriod, Enforcing }
public enum HealthStatus { Healthy, Stopped, Pending, Paused, ServiceMissing, InstallationMissing, Unknown }
public sealed record HealthSnapshot(HealthStatus Status, string Detail)
{
    public HealthDiagnostics? Diagnostics { get; init; }
    public bool IsHealthy => Status == HealthStatus.Healthy;
    public bool IsVerifiedUnhealthy => Status is not (HealthStatus.Healthy or HealthStatus.Unknown);
}
public sealed record HealthDiagnostics(bool? ServiceExists, string? ServiceState,
    bool? InstallationDirectoryExists, bool? InstallationAccessible);

// Retain the production exception path (unknown health), with partial observations for diagnostics.
public sealed class HealthCheckException(HealthSnapshot snapshot, Exception inner)
    : Exception(snapshot.Detail, inner)
{
    public HealthSnapshot Snapshot { get; } = snapshot;
}
public interface IWazuhHealthMonitor
{
    Task<HealthSnapshot> CheckAsync(CancellationToken cancellationToken);
}
public interface IWazuhRecoveryService
{
    Task<bool> TryRecoverAsync(CancellationToken cancellationToken);
}
public sealed record VpnSession(string Provider, string Id, string Name, string Status,
    string Technology, nint Handle, Guid CorrelationId, bool AllUsers)
{
    public string? DeviceType { get; init; }
    public string? DeviceName { get; init; }
    public string? LocalTunnelEndpoint { get; init; }
    public string? RemoteTunnelEndpoint { get; init; }
    public Guid? EntryId { get; init; }
    public ulong? LogonSessionId { get; init; }
    public uint? SubEntry { get; init; }
    public bool DisconnectSupported { get; init; } = true; // Existing RAS session contract.
    public string DetectionMethod { get; init; } = "Windows RAS APIs";
}
public enum DisconnectResult { Disconnected, AlreadyGone }
public interface IVpnSessionManager
{
    Task<IReadOnlyList<VpnSession>> GetActiveVpnSessionsAsync(CancellationToken cancellationToken);
    Task<DisconnectResult> DisconnectVpnSessionAsync(VpnSession session, CancellationToken cancellationToken);
    async Task<VpnDiscoveryReport> DiscoverAsync(CancellationToken cancellationToken) =>
        new(await GetActiveVpnSessionsAsync(cancellationToken), [], []);
}

public sealed record VpnCapabilities(bool DetectSessions, bool ReadMetadata, bool DisconnectSessions, string Mechanism);
public enum VpnProviderState { Available, NotInstalled, ObservationOnly, Unsupported, Error }
public sealed record VpnProviderReport(string Provider, VpnCapabilities Capabilities, VpnProviderState State,
    string Detail, IReadOnlyList<VpnSession> Sessions, string? Evidence = null);
public sealed record VpnEvidence(string Vendor, string Kind, string Name, string State, string Detail);
public sealed record VpnDiscoveryReport(IReadOnlyList<VpnSession> Sessions,
    IReadOnlyList<VpnProviderReport> Providers, IReadOnlyList<VpnEvidence> Evidence);
public interface IVpnProvider
{
    string Id { get; }
    VpnCapabilities Capabilities { get; }
    Task<VpnProviderReport> DiscoverAsync(CancellationToken cancellationToken);
    Task<DisconnectResult> DisconnectAsync(VpnSession session, CancellationToken cancellationToken);
}
public interface IGuardStateMachine
{
    GuardState State { get; }
    Task TickAsync(CancellationToken cancellationToken);
}
