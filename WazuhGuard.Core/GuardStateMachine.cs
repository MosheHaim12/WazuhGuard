using Microsoft.Extensions.Logging;

namespace WazuhGuard.Core;

/// <summary>One serialized observation/recovery/enforcement loop. Timers use monotonic time.</summary>
public sealed class GuardStateMachine(IWazuhHealthMonitor health, IWazuhRecoveryService recovery,
    IVpnSessionManager vpn, GuardOptions options, TimeProvider time, ILogger<GuardStateMachine> log)
    : IGuardStateMachine, IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private long? graceStarted;
    private HealthStatus? lastHealth;
    private string? lastVpnSet;
    private readonly HashSet<string> testReported = [];
    private readonly Dictionary<string, long> errors = [];
    public GuardState State { get; private set; } = GuardState.Healthy;

    public async Task TickAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var observation = await ObserveAsync(cancellationToken);
            if (!Accept(observation)) return;
            if (State == GuardState.Healthy)
            {
                if (observation.Status == HealthStatus.Stopped && options.RestartAttempts > 0)
                {
                    Transition(GuardState.Recovering, "Wazuh service stopped");
                    try { await recovery.TryRecoverAsync(cancellationToken); }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                    catch (Exception ex) { LogError("recovery", ex, "Wazuh recovery operation failed"); }
                    // A successful Start call alone is not evidence of a healthy installation.
                    observation = await ObserveAsync(cancellationToken);
                    if (!Accept(observation)) return;
                }
                EnterGrace("Verified Wazuh failure; allowing restart/upgrade grace");
                return;
            }
            if (State == GuardState.Recovering)
            {
                EnterGrace("Recovery interrupted or unsuccessful");
                return;
            }
            if (State == GuardState.GracePeriod)
            {
                if (graceStarted is null)
                {
                    EnterGrace("Verified observation resumed; starting a fresh grace period");
                    return;
                }
                if (time.GetElapsedTime(graceStarted.Value) < TimeSpan.FromSeconds(options.GracePeriodSeconds)) return;
                log.LogInformation("Grace period expired; performing final Wazuh health check");
                observation = await ObserveAsync(cancellationToken);
                if (!Accept(observation)) return;
                Transition(GuardState.Enforcing, "Final check verified Wazuh remains unavailable");
            }
            if (State == GuardState.Enforcing) await EnforceAsync(cancellationToken);
        }
        finally { gate.Release(); }
    }

    private async Task<HealthSnapshot> ObserveAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        HealthSnapshot observation;
        try { observation = await health.CheckAsync(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LogError("health", ex, "Unexpected monitoring exception; enforcement suspended");
            observation = new(HealthStatus.Unknown, "Health API error");
        }
        if (lastHealth != observation.Status)
        {
            log.LogInformation("Wazuh health changed: {HealthStatus}; {Detail}", observation.Status, observation.Detail);
            lastHealth = observation.Status;
        }
        return observation;
    }

    // False means there is no authority to disconnect on this tick.
    private bool Accept(HealthSnapshot observation)
    {
        if (observation.IsHealthy)
        {
            Transition(GuardState.Healthy, "Wazuh service running and installation present");
            graceStarted = null;
            lastVpnSet = null;
            testReported.Clear();
            return false;
        }
        if (observation.IsVerifiedUnhealthy) return true;
        Transition(GuardState.GracePeriod, "Health unknown; suspend enforcement and discard failure deadline");
        graceStarted = null;
        return false;
    }

    private void EnterGrace(string reason)
    {
        graceStarted = time.GetTimestamp();
        Transition(GuardState.GracePeriod, reason);
        log.LogInformation("Grace period entered for {GraceSeconds} seconds", options.GracePeriodSeconds);
    }

    private async Task EnforceAsync(CancellationToken ct)
    {
        IReadOnlyList<VpnSession> sessions;
        try { sessions = await vpn.GetActiveVpnSessionsAsync(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { LogError("vpn-enumeration", ex, "VPN discovery failed; will retry next check"); return; }
        var signature = string.Join("|", sessions.Select(s => s.Id).Order(StringComparer.Ordinal));
        if (signature != lastVpnSet)
        {
            log.LogInformation("VPN discovery completed: {Count} active VPN sessions", sessions.Count);
            if (sessions.Count == 0) log.LogInformation("No VPN currently connected");
            lastVpnSet = signature;
        }
        testReported.IntersectWith(sessions.Select(s => s.Id));
        foreach (var session in sessions)
        {
            ct.ThrowIfCancellationRequested();
            // Wazuh may recover while enumerating or while disconnecting another session.
            if (!Accept(await ObserveAsync(ct))) return;
            if (options.TestMode)
            {
                if (testReported.Add(session.Id))
                    log.LogWarning("TEST MODE: Would disconnect VPN session: {VpnName} ({VpnId}, {Technology})",
                        session.Name, session.Id, session.Technology);
                continue;
            }
            log.LogInformation("VPN session detected; disconnect attempt: {VpnName} {VpnId} {Technology}",
                session.Name, session.Id, session.Technology);
            try
            {
                var result = await vpn.DisconnectVpnSessionAsync(session, ct);
                log.LogInformation("VPN disconnect result: {Result}; {VpnName} {VpnId}", result, session.Name, session.Id);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { LogError("vpn-disconnect", ex, "VPN disconnect failed; will retry next check"); }
        }
    }

    private void Transition(GuardState next, string reason)
    {
        if (State == next) return;
        log.LogInformation("State transition {PreviousState} -> {NextState}: {Reason}", State, next, reason);
        State = next;
    }

    private void LogError(string key, Exception exception, string message)
    {
        if (errors.TryGetValue(key, out var previous) && time.GetElapsedTime(previous) < TimeSpan.FromMinutes(5)) return;
        errors[key] = time.GetTimestamp();
        log.LogError(exception, "{OperationMessage}", message);
    }
    public void Dispose() => gate.Dispose();
}
