using System.Reflection;
using WazuhGuard.Core;

namespace WazuhGuard;

public sealed class Worker(IGuardStateMachine stateMachine, GuardOptions options, TimeProvider time,
    ILogger<Worker> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        log.LogInformation("WazuhGuard {Version} startup — {Mode} MODE; configuration validation passed",
            Assembly.GetExecutingAssembly().GetName().Version, options.TestMode ? "TEST" : "PRODUCTION");
        log.LogInformation("Monitoring {ServiceName} in {InstallPath}; check {Interval}s; grace {Grace}s; recovery attempts {Attempts}",
            options.WazuhServiceName, options.WazuhInstallPath, options.CheckIntervalSeconds, options.GracePeriodSeconds, options.RestartAttempts);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await stateMachine.TickAsync(stoppingToken);
                await Task.Delay(TimeSpan.FromSeconds(options.CheckIntervalSeconds), time, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            log.LogCritical(ex, "WazuhGuard fatal worker exception; exiting nonzero for Windows Service Recovery");
            Serilog.Log.CloseAndFlush();
            Environment.Exit(1);
        }
        finally { log.LogInformation("WazuhGuard shutdown"); }
    }
}
