using WazuhGuard.Core;
using WazuhGuard.Monitoring;
using WazuhGuard.Recovery;
using WazuhGuard.Vpn;

namespace WazuhGuard;

public static class ProductionServices
{
    // Both service and manual entry points resolve precisely these implementations.
    public static IServiceCollection AddWazuhGuardPrimitives(this IServiceCollection services, GuardOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IWazuhServiceControl, WindowsWazuhService>();
        services.AddSingleton<IInstallationProbe, InstallationProbe>();
        services.AddSingleton<IWazuhHealthMonitor, WazuhHealthMonitor>();
        services.AddSingleton<IWazuhRecoveryService, WazuhRecoveryService>();
        services.AddSingleton<IRasApi, NativeRasApi>();
        services.AddSingleton<RasVpnSessionManager>();
        services.AddSingleton<IVendorClientLocator, VendorClientLocator>();
        services.AddSingleton<IVendorCommandRunner, VendorCommandRunner>();
        services.AddSingleton<IVpnEnvironmentProbe, WindowsVpnEnvironmentProbe>();
        services.AddSingleton<IVpnProvider, RasVpnProvider>();
        services.AddSingleton<IVpnProvider, CheckPointVpnProvider>();
        services.AddSingleton<IVpnProvider, FortiClientVpnProvider>();
        services.AddSingleton<IVpnSessionManager, CompositeVpnSessionManager>();
        return services;
    }
}
