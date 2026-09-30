using WazuhGuard.Core;
using WazuhGuard.Monitoring;

namespace WazuhGuard.Recovery;

public sealed class WazuhRecoveryService(IWazuhServiceControl service, GuardOptions options,
    TimeProvider time, ILogger<WazuhRecoveryService> log) : IWazuhRecoveryService, IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<bool> TryRecoverAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            for (var attempt = 1; attempt <= options.RestartAttempts; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                log.LogInformation("Wazuh recovery attempt {Attempt} of {Attempts}", attempt, options.RestartAttempts);
                try
                {
                    var status = service.GetStatus();
                    if (status == WazuhServiceStatus.Missing) break;
                    if (status == WazuhServiceStatus.Running) return true;
                    if (status == WazuhServiceStatus.Stopped) service.Start();
                    var start = time.GetTimestamp();
                    while (time.GetElapsedTime(start) < TimeSpan.FromSeconds(options.RestartTimeoutSeconds))
                    {
                        ct.ThrowIfCancellationRequested();
                        status = service.GetStatus();
                        if (status == WazuhServiceStatus.Running)
                        {
                            log.LogInformation("Wazuh recovery succeeded on attempt {Attempt}", attempt);
                            return true;
                        }
                        if (status is WazuhServiceStatus.Missing or WazuhServiceStatus.Stopped or WazuhServiceStatus.Paused) break;
                        await Task.Delay(TimeSpan.FromMilliseconds(250), time, ct);
                    }
                    log.LogWarning("Wazuh recovery attempt {Attempt} did not reach Running; status {Status}", attempt, status);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { log.LogWarning(ex, "Wazuh recovery attempt {Attempt} failed", attempt); }
                if (attempt < options.RestartAttempts)
                    await Task.Delay(TimeSpan.FromSeconds(options.RestartDelaySeconds), time, ct);
            }
            log.LogWarning("Wazuh recovery exhausted or service missing; allowing grace period");
            return false;
        }
        finally { gate.Release(); }
    }
    public void Dispose() => gate.Dispose();
}
