using System.Diagnostics;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using WazuhGuard.Core;

namespace WazuhGuard.Vpn;

public sealed class WindowsVpnEnvironmentProbe : IVpnEnvironmentProbe
{
    public IReadOnlyList<VpnEvidence> Inspect(CancellationToken ct)
    {
        var result = new List<VpnEvidence>();
        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                ct.ThrowIfCancellationRequested();
                var vendor = Classify(adapter.Name + " " + adapter.Description);
                if (vendor is null) continue;
                string addresses;
                try { addresses = string.Join(", ", adapter.GetIPProperties().UnicastAddresses.Select(a => a.Address.ToString())); }
                catch (Exception ex) { addresses = $"Unavailable: {ex.Message}"; }
                result.Add(new(vendor, "Adapter evidence (not session proof)", adapter.Name, adapter.OperationalStatus.ToString(),
                    $"Description={adapter.Description}; InterfaceId={adapter.Id}; Addresses={addresses}; safe disconnect unsupported from adapter evidence."));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { result.Add(new("Unknown", "InventoryError", "NetworkInterface", "Unknown", ex.Message)); }
        try
        {
            var services = ServiceController.GetServices();
            try
            {
                foreach (var service in services)
                {
                    ct.ThrowIfCancellationRequested();
                    var vendor = Classify(service.ServiceName + " " + service.DisplayName);
                    if (vendor is null) continue;
                    string state;
                    try { state = service.Status.ToString(); } catch (Exception ex) { state = $"Unknown: {ex.Message}"; }
                    result.Add(new(vendor, "Service evidence (not session proof)", service.ServiceName, state, service.DisplayName));
                }
            }
            finally { foreach (var service in services) service.Dispose(); }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { result.Add(new("Unknown", "InventoryError", "Services", "Unknown", ex.Message)); }
        return result;
    }

    public static string? Classify(string description)
    {
        if (description.Contains("Check Point", StringComparison.OrdinalIgnoreCase) ||
            description.Contains("CheckPoint", StringComparison.OrdinalIgnoreCase) || description.Contains("TracSrvWrapper", StringComparison.OrdinalIgnoreCase)) return "CheckPoint";
        if (description.Contains("Forti", StringComparison.OrdinalIgnoreCase)) return "FortiClient";
        if (new[] { "vpn", "wireguard", "openvpn", "wintun", "tap-windows", "anyconnect", "globalprotect" }
            .Any(s => description.Contains(s, StringComparison.OrdinalIgnoreCase))) return "Unsupported/Unknown";
        return null;
    }
}
