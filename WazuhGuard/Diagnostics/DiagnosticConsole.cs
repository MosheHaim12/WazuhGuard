using System.Text;

namespace WazuhGuard.Diagnostics;

internal static class DiagnosticConsole
{
    // The manual CI artifact is published as a Console executable, so Windows/PowerShell
    // supplies the console or redirected handles before Main starts. Do not AttachConsole
    // or replace Win32 standard handles here: doing that after PowerShell has launched the
    // process can interleave the prompt with diagnostic output.
    //
    // The installed service remains WinExe and never enters DiagnosticHost without explicit
    // CLI arguments, so this has no effect on normal service startup.
    public static bool Attach()
    {
        try
        {
            using var stdout = Console.OpenStandardOutput();
            if (stdout == Stream.Null || !stdout.CanWrite) return false;

            Console.OutputEncoding = new UTF8Encoding(false);
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false))
            {
                AutoFlush = true
            });
            Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false))
            {
                AutoFlush = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }
}
