using System.ComponentModel;
using System.ServiceProcess;
using WazuhGuard.Core;

namespace WazuhGuard.Monitoring;

public enum WazuhServiceStatus { Missing, Stopped, Running, Paused, Pending, StartPending, StopPending, ContinuePending, PausePending }
public interface IWazuhServiceControl
{
    WazuhServiceStatus GetStatus();
    void Start();
}
public interface IInstallationProbe { bool Exists(); }

public sealed class WindowsWazuhService(GuardOptions options) : IWazuhServiceControl
{
    public WazuhServiceStatus GetStatus()
    {
        using var service = new ServiceController(options.WazuhServiceName);
        try
        {
            return service.Status switch
            {
                ServiceControllerStatus.Running => WazuhServiceStatus.Running,
                ServiceControllerStatus.Stopped => WazuhServiceStatus.Stopped,
                ServiceControllerStatus.Paused => WazuhServiceStatus.Paused,
                ServiceControllerStatus.StartPending => WazuhServiceStatus.StartPending,
                ServiceControllerStatus.StopPending => WazuhServiceStatus.StopPending,
                ServiceControllerStatus.ContinuePending => WazuhServiceStatus.ContinuePending,
                ServiceControllerStatus.PausePending => WazuhServiceStatus.PausePending,
                _ => WazuhServiceStatus.Pending
            };
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: 1060 })
        { return WazuhServiceStatus.Missing; }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1060)
        { return WazuhServiceStatus.Missing; }
        // Access denied and SCM failures propagate as unknown health, never as missing.
    }

    public void Start()
    {
        using var service = new ServiceController(options.WazuhServiceName);
        service.Start();
    }
}

public sealed class InstallationProbe(GuardOptions options) : IInstallationProbe
{
    public bool Exists()
    {
        try { return (File.GetAttributes(options.WazuhInstallPath) & FileAttributes.Directory) != 0; }
        catch (DirectoryNotFoundException) { return false; }
        catch (FileNotFoundException) { return false; }
        // Directory.Exists suppresses permission and I/O errors; do not use it for enforcement evidence.
    }
}
