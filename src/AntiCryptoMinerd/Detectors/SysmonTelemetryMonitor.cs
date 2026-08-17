using System.Diagnostics.Eventing.Reader;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

public sealed class SysmonTelemetryMonitor : IThreatDetector
{
    private DateTime _lastReadUtc = DateTime.UtcNow;
    public string Name => "sysmon";

    public Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken) => Task.Run(() =>
    {
        var alerts = new List<DetectionAlert>();
        try
        {
            var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, "*[System[(EventID=1)]]");
            using var reader = new EventLogReader(query); EventRecord? record;
            while ((record = reader.ReadEvent()) is not null)
            {
                using (record)
                {
                    if (record.TimeCreated?.ToUniversalTime() <= _lastReadUtc) continue;
                    var text = record.FormatDescription() ?? string.Empty;
                    if (text.Contains("xmrig", StringComparison.OrdinalIgnoreCase) || text.Contains("stratum", StringComparison.OrdinalIgnoreCase)) alerts.Add(new DetectionAlert("sysmon", 80, ["Sysmon process creation matched miner indicator"], ResourceContext: text));
                }
            }
            _lastReadUtc = DateTime.UtcNow;
        }
        catch (Exception ex) { context.Logger.WriteAsync("ERROR", $"Sysmon telemetry unavailable: {ex.Message}", cancellationToken).GetAwaiter().GetResult(); }
        return (IReadOnlyList<DetectionAlert>)alerts;
    }, cancellationToken);
}
