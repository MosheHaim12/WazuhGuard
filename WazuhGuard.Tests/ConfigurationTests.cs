using WazuhGuard.Configuration;
using WazuhGuard.Core;

namespace WazuhGuard.Tests;

public sealed class ConfigurationTests
{
    [Fact] public void DefaultsAreSafeAndValid()
    {
        var options = new GuardOptions();
        options.Validate();
        Assert.True(options.TestMode);
        Assert.Equal(120, options.GracePeriodSeconds);
    }
    [Theory]
    [InlineData("relative")]
    [InlineData("C:\\")]
    [InlineData("C:\\agent\\..\\Windows")]
    [InlineData("\\\\server\\agent")]
    [InlineData("C:\\agent:stream")]
    public void InvalidPathsRejected(string path) => Assert.Throws<ArgumentException>(() => new GuardOptions { WazuhInstallPath = path }.Validate());

    [Fact] public void InvalidIntervalsAndSelfMonitoringRejected()
    {
        Assert.Throws<ArgumentException>(() => new GuardOptions { CheckIntervalSeconds = 0 }.Validate());
        Assert.Throws<ArgumentException>(() => new GuardOptions { GracePeriodSeconds = -1 }.Validate());
        Assert.Throws<ArgumentException>(() => new GuardOptions { RestartAttempts = 11 }.Validate());
        Assert.Throws<ArgumentException>(() => new GuardOptions { WazuhServiceName = "WazuhGuard" }.Validate());
    }
    [Theory]
    [InlineData("{}")]
    [InlineData("{\"WazuhGuard\":null}")]
    [InlineData("{\"WazuhGuard\":{\"TestMode\":\"false\"}}")]
    [InlineData("{\"WazuhGuard\":{\"TestMode\":false,\"TestMode\":true}}")]
    [InlineData("{\"WazuhGuard\":{\"TestMod\":false}}")]
    [InlineData("{\"WazuhGuard\":{\"GracePeriodSeconds\":0}}")]
    public void MalformedOrAmbiguousConfigurationRejected(string json)
    {
        var path = Path.GetTempFileName();
        try { File.WriteAllText(path, json); Assert.ThrowsAny<Exception>(() => ConfigurationFile.Read(path)); }
        finally { File.Delete(path); }
    }
    [Fact] public void ExplicitProductionModeAccepted()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "{\"WazuhGuard\":{\"TestMode\":false}}");
            Assert.False(ConfigurationFile.Read(path).TestMode);
        }
        finally { File.Delete(path); }
    }
}
