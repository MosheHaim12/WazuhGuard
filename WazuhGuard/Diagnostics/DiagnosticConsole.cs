using System.Runtime.InteropServices;
using System.Text;

namespace WazuhGuard.Diagnostics;

internal static class DiagnosticConsole
{
    // Keep the service a WinExe. Explicit CLI invocations attach only to an existing terminal;
    // never allocate a new console or show UI. Preserve inherited pipe/file redirection.
    public static bool Attach()
    {
        var stdout = GetStdHandle(-11);
        var stderr = GetStdHandle(-12);
        var preserveOut = IsUsable(stdout);
        var preserveError = IsUsable(stderr);
        AttachConsole(uint.MaxValue);
        if (preserveOut) SetStdHandle(-11, stdout);
        if (preserveError) SetStdHandle(-12, stderr);
        if (!IsUsable(GetStdHandle(-11))) return false; // No visible selection => no operation.
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
        Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
        return true;
    }

    private static bool IsUsable(nint handle) => handle != 0 && handle != -1 && GetFileType(handle) != 0;
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GetStdHandle(int which);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetStdHandle(int which, nint handle);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(nint handle);
}
