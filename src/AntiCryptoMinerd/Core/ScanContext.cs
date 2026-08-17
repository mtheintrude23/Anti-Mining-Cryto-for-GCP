using AntiCryptoMinerd.Configuration;
using AntiCryptoMinerd.Infrastructure;

namespace AntiCryptoMinerd.Core;

public sealed class ScanContext(ConfigProvider config, SecurityLogger logger, GcpMetadataClient gcp)
{
    public ConfigProvider ConfigProvider { get; } = config;
    public AgentConfig Config => ConfigProvider.Current;
    public SecurityLogger Logger { get; } = logger;
    public GcpMetadataClient Gcp { get; } = gcp;
    public string Hostname { get; } = Environment.MachineName;
}
