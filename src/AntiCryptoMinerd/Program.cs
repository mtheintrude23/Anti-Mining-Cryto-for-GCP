using AntiCryptoMinerd.Configuration;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Detectors;
using AntiCryptoMinerd.Infrastructure;
using AntiCryptoMinerd.Services;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "AntiCryptoMinerd");
builder.Logging.ClearProviders();
builder.Services.AddSingleton<ConfigProvider>();
builder.Services.AddSingleton<SecurityLogger>();
builder.Services.AddSingleton<GcpMetadataClient>();
builder.Services.AddSingleton<DiscordNotifier>();
builder.Services.AddSingleton<RemediationEngine>();
builder.Services.AddSingleton<ProcessInspector>();
builder.Services.AddSingleton<NetworkInspector>();
builder.Services.AddSingleton<PersistenceMonitor>();
builder.Services.AddSingleton<DriverInspector>();
builder.Services.AddSingleton<ContainerInspector>();
builder.Services.AddSingleton<SysmonTelemetryMonitor>();
builder.Services.AddHostedService<SecurityWorker>();

await builder.Build().RunAsync();
