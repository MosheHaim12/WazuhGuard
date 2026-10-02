using System.Reflection;
using System.Security.Principal;
using WazuhGuard.Configuration;

namespace WazuhGuard.Diagnostics;

internal static class DiagnosticHost
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (!DiagnosticConsole.Attach()) return 2;
        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cts.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            DiagnosticCommand command;
            try { command = DiagnosticCommand.Parse(args); }
            catch (ArgumentException ex) { Console.WriteLine($"ERROR: {ex.Message}\n{DiagnosticCommand.Help}"); return 2; }
            if (command.Operation == DiagnosticOperation.Help) { Console.WriteLine(DiagnosticCommand.Help); return 0; }
            using var identity = WindowsIdentity.GetCurrent();
            Console.WriteLine($"WazuhGuard {Assembly.GetExecutingAssembly().GetName().Version} manual diagnostic: {command.Operation}");
            Console.WriteLine($"UTC: {DateTimeOffset.UtcNow:O}; account: {identity.Name}; process: {Environment.ProcessId}; 64-bit: {Environment.Is64BitProcess}");
            Console.WriteLine($"Configuration: {ConfigurationFile.ConfigPath}");
            Console.WriteLine("Context: current account, not the service's LocalSystem account. No state machine or monitoring worker is started.");
            GuardOptions options;
            if (File.Exists(ConfigurationFile.ConfigPath))
            {
                options = ConfigurationFile.Read(ConfigurationFile.ConfigPath);
                Console.WriteLine($"Mode: {(options.TestMode ? "TEST" : "PRODUCTION")}; TestMode={options.TestMode}");
            }
            else
            {
                // Manual diagnostics must work before the MSI/service is installed. Missing configuration
                // always falls back to safe test defaults, so it can never enable a disconnect operation.
                options = new GuardOptions();
                options.Validate();
                Console.WriteLine("Configuration file not found; using built-in safe diagnostic defaults.");
                Console.WriteLine($"Mode: TEST; TestMode={options.TestMode}");
            }
            var services = new ServiceCollection();
            services.AddLogging(logging => logging.AddSimpleConsole(format =>
            { format.SingleLine = true; format.TimestampFormat = "HH:mm:ss "; }));
            services.AddWazuhGuardPrimitives(options);
            services.AddSingleton<TextWriter>(Console.Out);
            services.AddTransient<DiagnosticRunner>();
            using var provider = services.BuildServiceProvider();
            var exitCode = await provider.GetRequiredService<DiagnosticRunner>().RunAsync(command, cts.Token);
            Console.WriteLine($"Diagnostic exit code: {exitCode}");
            return exitCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAIL: diagnostic startup/configuration error; no further operations will run.\n{ex}");
            return 3;
        }
        finally { Console.CancelKeyPress -= cancel; }
    }
}
