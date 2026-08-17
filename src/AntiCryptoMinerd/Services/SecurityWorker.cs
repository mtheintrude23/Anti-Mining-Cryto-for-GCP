using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Detectors;
using AntiCryptoMinerd.Infrastructure;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Services;

public sealed class SecurityWorker : BackgroundService
{
    private readonly ScanContext _context;
    private readonly IReadOnlyList<IThreatDetector> _detectors;
    private readonly RemediationEngine _remediation;
    private readonly DiscordNotifier _notifier;

    public SecurityWorker(ConfigProvider config, SecurityLogger logger, GcpMetadataClient gcp, ProcessInspector process, NetworkInspector network, PersistenceMonitor persistence, DriverInspector driver, ContainerInspector containers, SysmonTelemetryMonitor sysmon, RemediationEngine remediation, DiscordNotifier notifier)
    {
        _context = new ScanContext(config, logger, gcp);
        _detectors = [process, network, persistence, driver, containers, sysmon];
        _remediation = remediation;
        _notifier = notifier;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await _context.Logger.WriteAsync("INFO", "AntiCryptoMinerd service started.", stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var enabled = _detectors.Where(IsEnabled).Select(d => ScanOneAsync(d, stoppingToken));
                var alerts = (await Task.WhenAll(enabled)).SelectMany(x => x).ToList();
                foreach (var alert in alerts.Where(a => a.Confidence >= _context.Config.ConfidenceThreshold)) await HandleAsync(alert, stoppingToken);
            }
            catch (Exception ex) { await _context.Logger.WriteAsync("ERROR", $"Scan cycle failed: {ex.Message}", stoppingToken); }

            try { await Task.Delay(TimeSpan.FromSeconds(_context.Config.ScanIntervalSeconds), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private bool IsEnabled(IThreatDetector detector) => detector.Name switch
    {
        "persistence" => _context.Config.EnableFim,
        "drivers" => _context.Config.EnableDriverCheck,
        "containers" => _context.Config.EnableContainerCheck,
        "sysmon" => _context.Config.EnableSysmonTelemetry,
        _ => true
    };

    private async Task<IReadOnlyList<DetectionAlert>> ScanOneAsync(IThreatDetector detector, CancellationToken token)
    {
        try { return await detector.ScanAsync(_context, token); }
        catch (Exception ex) { await _context.Logger.WriteAsync("ERROR", $"Detector {detector.Name} failed: {ex.Message}", token); return []; }
    }

    private async Task HandleAsync(DetectionAlert alert, CancellationToken token)
    {
        await _remediation.ApplyAsync(alert, _context, token);
        await _context.Logger.WriteAsync("WARN", $"{alert.DetectionType}: confidence={alert.Confidence}; action={alert.ActionTaken}; reasons={string.Join(", ", alert.Reasons)}", token);
        await _notifier.SendAsync(alert, _context, token);
        if (alert.Confidence >= 100 && _context.Config.GcpDeleteSelf && !_context.Config.DryRun)
        {
            var deleted = await _context.Gcp.DeleteSelfAsync(_context.Config, token);
            await _context.Logger.WriteAsync("WARN", deleted ? "GCP self-deletion request accepted." : "GCP self-deletion request was not accepted.", token);
        }
    }
}
