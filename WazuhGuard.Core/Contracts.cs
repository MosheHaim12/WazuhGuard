namespace WazuhGuard.Core;

public enum GuardState { Healthy, Recovering, GracePeriod, Enforcing }
public enum HealthStatus { Healthy, Stopped, Pending, Paused, ServiceMissing, InstallationMissing, Unknown }
public sealed record HealthSnapshot(HealthStatus Status, string Detail)
{
    public bool IsHealthy => Status == HealthStatus.Healthy;
    public bool IsVerifiedUnhealthy => Status is not (HealthStatus.Healthy or HealthStatus.Unknown);
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
    string Technology, nint Handle, Guid CorrelationId, bool AllUsers);
public enum DisconnectResult { Disconnected, AlreadyGone }
public interface IVpnSessionManager
{
    Task<IReadOnlyList<VpnSession>> GetActiveVpnSessionsAsync(CancellationToken cancellationToken);
    Task<DisconnectResult> DisconnectVpnSessionAsync(VpnSession session, CancellationToken cancellationToken);
}
public interface IGuardStateMachine
{
    GuardState State { get; }
    Task TickAsync(CancellationToken cancellationToken);
}
