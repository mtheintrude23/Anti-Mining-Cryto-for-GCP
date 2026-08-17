using AntiCryptoMinerd.Configuration;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Detectors;
using AntiCryptoMinerd.Infrastructure;
using AntiCryptoMinerd.Services;

// Utility mode: encrypt a secret for storage in config.json instead of starting the service.
// Usage: AntiCryptoMinerd.exe --protect-webhook "https://discord.com/api/webhooks/..."
// Must be run elevated on the target machine, since DPAPI LocalMachine keys are per-host.
if (args.Length == 2 && args[0] == "--protect-webhook")
{
    Console.WriteLine(SecretProtector.Protect(args[1]));
    return;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "AntiCryptoMinerd");
builder.Logging.ClearProviders();
builder.Services.AddSingleton<ConfigProvider>();
builder.Services.AddSingleton<SecurityLogger>();
builder.Services.AddSingleton<GcpMetadataClient>();
builder.Services.AddSingleton<DiscordNotifier>();
builder.Services.AddSingleton<RemediationEngine>();
builder.Services.AddSingleton<ShutdownConfirmationGate>();
builder.Services.AddSingleton<ProcessInspector>();
builder.Services.AddSingleton<NetworkInspector>();
builder.Services.AddSingleton<PersistenceMonitor>();
builder.Services.AddSingleton<DriverInspector>();
builder.Services.AddSingleton<ContainerInspector>();
builder.Services.AddSingleton<SysmonTelemetryMonitor>();
builder.Services.AddHostedService<SecurityWorker>();

await builder.Build().RunAsync();
