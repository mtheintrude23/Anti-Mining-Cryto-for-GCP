namespace AntiCryptoMinerd.Configuration;

public sealed class AgentConfig
{
    public string WebhookUrl { get; init; } = string.Empty;
    public int ScanIntervalSeconds { get; init; } = 30;
    public int ConfidenceThreshold { get; init; } = 70;
    public double EntropyThreshold { get; init; } = 7.4;
    public int EntropySampleBytes { get; init; } = 65536;
    public bool DryRun { get; init; } = true;
    public bool EnableRemediation { get; init; } = true;
    public bool EnableFim { get; init; } = true;
    public bool EnableDriverCheck { get; init; } = true;
    public bool EnableContainerCheck { get; init; } = true;
    public bool EnableSysmonTelemetry { get; init; }
    public bool GcpDeleteSelf { get; init; }
    public string GcpProjectId { get; init; } = string.Empty;
    public string GcpZone { get; init; } = string.Empty;
    public string GcpInstanceName { get; init; } = string.Empty;
    public string[] Allowlist { get; init; } = [];
    public string[] BlacklistIps { get; init; } = [];
    public int[] PoolPorts { get; init; } = [3333, 4444, 5555, 7777, 8000, 9000, 14444, 18081];

    public void Validate()
    {
        if (ScanIntervalSeconds is < 5 or > 86400) throw new InvalidOperationException("scanIntervalSeconds must be between 5 and 86400.");
        if (ConfidenceThreshold is < 1 or > 100) throw new InvalidOperationException("confidenceThreshold must be between 1 and 100.");
        if (EntropyThreshold is < 0 or > 8) throw new InvalidOperationException("entropyThreshold must be between 0 and 8.");
        if (EntropySampleBytes is < 1024 or > 1048576) throw new InvalidOperationException("entropySampleBytes must be between 1024 and 1048576.");
        if ((!string.IsNullOrWhiteSpace(GcpProjectId) && !GcpIdentifier.IsValidProject(GcpProjectId)) ||
            (!string.IsNullOrWhiteSpace(GcpZone) && !GcpIdentifier.IsValidZone(GcpZone)) ||
            (!string.IsNullOrWhiteSpace(GcpInstanceName) && !GcpIdentifier.IsValidInstance(GcpInstanceName)))
            throw new InvalidOperationException("Configured GCP identifiers are invalid.");
    }
}

public static class GcpIdentifier
{
    public static bool IsValidProject(string value) => System.Text.RegularExpressions.Regex.IsMatch(value ?? string.Empty, "^[a-z][a-z0-9-]{4,28}[a-z0-9]$");
    public static bool IsValidZone(string value) => System.Text.RegularExpressions.Regex.IsMatch(value ?? string.Empty, "^[a-z]+-[a-z]+[0-9]-[a-z]$");
    public static bool IsValidInstance(string value) => System.Text.RegularExpressions.Regex.IsMatch(value ?? string.Empty, "^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$");
}
