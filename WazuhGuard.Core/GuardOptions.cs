namespace WazuhGuard.Core;

public sealed record GuardOptions
{
    public string WazuhServiceName { get; init; } = "WazuhSvc";
    public string WazuhInstallPath { get; init; } = @"C:\Program Files (x86)\ossec-agent";
    public int CheckIntervalSeconds { get; init; } = 10;
    public int GracePeriodSeconds { get; init; } = 120;
    public int RestartAttempts { get; init; } = 3;
    public int RestartTimeoutSeconds { get; init; } = 15;
    public int RestartDelaySeconds { get; init; } = 5;
    public int VpnDisconnectTimeoutSeconds { get; init; } = 10;
    public bool TestMode { get; init; } = true;

    public void Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(WazuhServiceName) || WazuhServiceName.Length > 256 ||
            WazuhServiceName.IndexOfAny(['/', '\\', '\0']) >= 0 ||
            WazuhServiceName.Equals("WazuhGuard", StringComparison.OrdinalIgnoreCase))
            errors.Add("WazuhServiceName must be a valid service name other than WazuhGuard.");
        // Check Windows path syntax independently of the OS used by the test runner.
        if (string.IsNullOrWhiteSpace(WazuhInstallPath) || WazuhInstallPath.Length < 4 ||
            !char.IsAsciiLetter(WazuhInstallPath[0]) || WazuhInstallPath[1] != ':' ||
            WazuhInstallPath[2] != '\\' || WazuhInstallPath.IndexOfAny(['*', '?', '"', '<', '>', '|', '\0']) >= 0 ||
            WazuhInstallPath[3..].Contains(':') ||
            WazuhInstallPath.Split('\\').Any(part => part is ".." or "."))
            errors.Add("WazuhInstallPath must be an absolute local Windows directory path without traversal or wildcards.");
        Range(CheckIntervalSeconds, 1, 300, nameof(CheckIntervalSeconds));
        Range(GracePeriodSeconds, 1, 86400, nameof(GracePeriodSeconds));
        Range(RestartAttempts, 0, 10, nameof(RestartAttempts));
        Range(RestartTimeoutSeconds, 1, 120, nameof(RestartTimeoutSeconds));
        Range(RestartDelaySeconds, 1, 300, nameof(RestartDelaySeconds));
        Range(VpnDisconnectTimeoutSeconds, 1, 60, nameof(VpnDisconnectTimeoutSeconds));
        if (errors.Count != 0) throw new ArgumentException(string.Join(" ", errors));
        return;

        void Range(int value, int min, int max, string name)
        {
            if (value < min || value > max) errors.Add($"{name} must be between {min} and {max}.");
        }
    }
}
