using System.Diagnostics;
using Microsoft.Extensions.Hosting.WindowsServices;
using Serilog;
using Serilog.Formatting.Json;
using WazuhGuard.Configuration;
using WazuhGuard.Core;
using WazuhGuard.Monitoring;
using WazuhGuard.Recovery;
using WazuhGuard.Vpn;

namespace WazuhGuard;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 2;
        try
        {
            var logDirectory = Path.Combine(ConfigurationFile.DataDirectory, "logs");
            Directory.CreateDirectory(logDirectory);
            Log.Logger = new LoggerConfiguration().MinimumLevel.Information()
                .Enrich.FromLogContext()
                .WriteTo.File(new JsonFormatter(renderMessage: true), Path.Combine(logDirectory, "wazuhguard-.jsonl"),
                    rollingInterval: RollingInterval.Day, fileSizeLimitBytes: 10 * 1024 * 1024,
                    rollOnFileSizeLimit: true, retainedFileCountLimit: 31, buffered: false)
                .CreateLogger();
            Serilog.Debugging.SelfLog.Enable(message => WriteEvent(message, EventLogEntryType.Error));
            var options = ConfigurationFile.Read(ConfigurationFile.ConfigPath);
            Log.Information("Configuration validation passed; {Mode} MODE; source {ConfigPath}",
                options.TestMode ? "TEST" : "PRODUCTION", ConfigurationFile.ConfigPath);
            if (args is ["--validate-configuration"]) return 0;
            if (args.Length != 0 || !WindowsServiceHelpers.IsWindowsService())
            {
                Log.Error("WazuhGuard must be started by the Windows Service Control Manager; use the MSI installer");
                return 2;
            }
            // Do not allow current-directory, environment or command-line overrides of security settings.
            var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
            { DisableDefaults = true, ContentRootPath = AppContext.BaseDirectory });
            builder.Services.AddWindowsService(o => o.ServiceName = "WazuhGuard");
            builder.Logging.ClearProviders();
            builder.Services.AddSerilog();
            builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(90));
            builder.Services.AddSingleton(options);
            builder.Services.AddSingleton(TimeProvider.System);
            builder.Services.AddSingleton<IWazuhServiceControl, WindowsWazuhService>();
            builder.Services.AddSingleton<IInstallationProbe, InstallationProbe>();
            builder.Services.AddSingleton<IWazuhHealthMonitor, WazuhHealthMonitor>();
            builder.Services.AddSingleton<IWazuhRecoveryService, WazuhRecoveryService>();
            builder.Services.AddSingleton<IRasApi, NativeRasApi>();
            builder.Services.AddSingleton<IVpnSessionManager, RasVpnSessionManager>();
            builder.Services.AddSingleton<IGuardStateMachine, GuardStateMachine>();
            builder.Services.AddHostedService<Worker>();
            using var host = builder.Build();
            await host.RunAsync();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "WazuhGuard startup or host failure; service will not enforce with invalid configuration");
            WriteEvent($"WazuhGuard startup/host failure: {ex}", EventLogEntryType.Error);
            return 1;
        }
        finally { await Log.CloseAndFlushAsync(); }
    }

    private static void WriteEvent(string message, EventLogEntryType type)
    {
        try { EventLog.WriteEntry("WazuhGuard", message.Length > 30000 ? message[..30000] : message, type); }
        catch { /* Logging must not display UI or cause recursive failures if Event Log is unavailable. */ }
    }
}
