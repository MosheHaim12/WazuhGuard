using WazuhGuard.Core;

namespace WazuhGuard.Monitoring;

public sealed class WazuhHealthMonitor(IWazuhServiceControl service, IInstallationProbe installation) : IWazuhHealthMonitor
{
    public Task<HealthSnapshot> CheckAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var status = service.GetStatus();
        var exists = installation.Exists();
        var result = !exists
            ? new HealthSnapshot(HealthStatus.InstallationMissing, $"Installation directory missing; service status: {status}")
            : status switch
            {
                WazuhServiceStatus.Running => new(HealthStatus.Healthy, "Service running; installation directory present"),
                WazuhServiceStatus.Missing => new(HealthStatus.ServiceMissing, "Wazuh service missing"),
                WazuhServiceStatus.Stopped => new(HealthStatus.Stopped, "Wazuh service stopped"),
                WazuhServiceStatus.Paused => new(HealthStatus.Paused, "Wazuh service paused"),
                _ => new(HealthStatus.Pending, "Wazuh service is in a pending transition")
            };
        return Task.FromResult(result);
    }
}
