using WazuhGuard.Core;

namespace WazuhGuard.Monitoring;

public sealed class WazuhHealthMonitor(IWazuhServiceControl service, IInstallationProbe installation) : IWazuhHealthMonitor
{
    public Task<HealthSnapshot> CheckAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        WazuhServiceStatus? status = null;
        bool? exists = null;
        bool? accessible = null;
        var errors = new List<Exception>();
        try { status = service.GetStatus(); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { errors.Add(ex); }
        cancellationToken.ThrowIfCancellationRequested();
        // Collect both observations even when one query fails; neither error is evidence of absence.
        try { exists = installation.Exists(); accessible = exists.Value ? true : null; }
        catch (UnauthorizedAccessException ex) { accessible = false; errors.Add(ex); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { errors.Add(ex); }
        var diagnostics = new HealthDiagnostics(status is null ? null : status != WazuhServiceStatus.Missing,
            status?.ToString(), exists, accessible);
        if (errors.Count > 0)
            throw new HealthCheckException(new(HealthStatus.Unknown, "One or more health queries failed; health is Unknown")
                { Diagnostics = diagnostics }, new AggregateException(errors));
        var result = exists == false
            ? new HealthSnapshot(HealthStatus.InstallationMissing, $"Installation directory missing; service status: {status}")
            : status switch
            {
                WazuhServiceStatus.Running => new(HealthStatus.Healthy, "Service running; installation directory present"),
                WazuhServiceStatus.Missing => new(HealthStatus.ServiceMissing, "Wazuh service missing"),
                WazuhServiceStatus.Stopped => new(HealthStatus.Stopped, "Wazuh service stopped"),
                WazuhServiceStatus.Paused => new(HealthStatus.Paused, "Wazuh service paused"),
                _ => new(HealthStatus.Pending, "Wazuh service is in a pending transition")
            };
        return Task.FromResult(result with { Diagnostics = diagnostics });
    }
}
