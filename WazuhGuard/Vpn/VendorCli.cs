using System.Diagnostics;
using System.Text;

namespace WazuhGuard.Vpn;

public sealed record VendorClient(string Path, Version Version, string Product, string Company);
public sealed record VendorCommandResult(int ExitCode, string Output, string Error, bool Truncated = false);
public interface IVendorClientLocator { VendorClient? Find(string vendor); }
public interface IVendorCommandRunner
{
    Task<VendorCommandResult> RunAsync(VendorClient client, IReadOnlyList<string> arguments, CancellationToken ct);
}

public sealed class VendorClientLocator : IVendorClientLocator
{
    public VendorClient? Find(string vendor)
    {
        var relativePaths = vendor switch
        {
            "CheckPoint" => new[] { @"CheckPoint\Endpoint Connect\trac.exe", @"CheckPoint\Endpoint Security\Endpoint Connect\trac.exe", @"CheckPoint\TRAC\trac.exe" },
            "FortiClient" => [@"Fortinet\FortiClient\FortiVPN.exe"],
            _ => throw new NotSupportedException("Unknown vendor executable.")
        };
        var roots = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) }.Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase);
        var found = roots.SelectMany(root => relativePaths.Select(relative => Path.Combine(root, relative)))
            .Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (found.Length == 0) return null;
        if (found.Length != 1) throw new InvalidOperationException("Multiple vendor CLI installations found; refusing to choose an ambiguous executable: " + string.Join(", ", found));
        var path = found[0];
        // Never search PATH/current directory or follow a vendor-directory junction into user-writable locations.
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Vendor executable path traverses a reparse point; refusing execution.");
        }
        var version = FileVersionInfo.GetVersionInfo(path);
        var company = version.CompanyName ?? "";
        var expected = vendor == "CheckPoint" ? "Check Point" : "Fortinet";
        if (!company.Contains(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Vendor executable metadata does not identify {expected}; refusing execution: {path}");
        // Metadata is identification, not an Authenticode assertion. Program Files ACLs are the trust boundary.
        return new(path, new(version.FileMajorPart, version.FileMinorPart, version.FileBuildPart, version.FilePrivatePart),
            version.ProductName ?? "Unknown", company);
    }
}

public sealed class VendorCommandRunner : IVendorCommandRunner
{
    public async Task<VendorCommandResult> RunAsync(VendorClient client, IReadOnlyList<string> arguments, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var start = new ProcessStartInfo(client.Path)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
            RedirectStandardError = true, RedirectStandardInput = true, WorkingDirectory = Path.GetDirectoryName(client.Path)!
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = new Process { StartInfo = start };
        if (!process.Start()) throw new IOException("Could not start the vendor CLI utility.");
        process.StandardInput.Close(); // A diagnostic must not wait indefinitely for interactive input.
        var stdout = ReadBoundedAsync(process.StandardOutput, deadline.Token);
        var stderr = ReadBoundedAsync(process.StandardError, deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            var output = await stdout;
            var error = await stderr;
            return new(process.ExitCode, output.Text, error.Text, output.Truncated || error.Truncated);
        }
        catch
        {
            // Only terminate the short-lived command process launched by this invocation, never a
            // pre-existing VPN GUI/service, arbitrary PID or process tree. This is timeout cleanup.
            try { if (!process.HasExited) process.Kill(entireProcessTree: false); } catch (InvalidOperationException) { }
            try { await Task.WhenAll(stdout, stderr); } catch (OperationCanceledException) { }
            ct.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested) throw new TimeoutException("Vendor CLI did not finish within 10 seconds; connection state is unknown.");
            throw;
        }
    }

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(StreamReader reader, CancellationToken ct)
    {
        var text = new StringBuilder();
        var buffer = new char[2048];
        var truncated = false;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), ct)) != 0)
        {
            var take = Math.Min(count, 65536 - text.Length);
            text.Append(buffer, 0, take);
            if (take < count) truncated = true;
        }
        return (text.ToString(), truncated);
    }
}
