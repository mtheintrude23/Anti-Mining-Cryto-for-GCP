using System.Management;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

public sealed class DriverInspector : IThreatDetector
{
    private readonly HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private bool _initialized;
    public string Name => "drivers";

    public Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken) => Task.Run(() =>
    {
        var alerts = new List<DetectionAlert>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, State FROM Win32_SystemDriver WHERE State = 'Running'");
            foreach (ManagementObject driver in searcher.Get())
            {
                var name = driver["Name"]?.ToString() ?? "unknown"; var path = NormalizeDriverPath(driver["PathName"]?.ToString());
                var reasons = new List<string>(); var score = 0;
                if (_initialized && _baseline.Add(name)) { score += 45; reasons.Add("Driver not present in baseline"); }
                else _baseline.Add(name);
                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path) && !AuthenticodeInspector.Inspect(path).ChainValid) { score += 40; reasons.Add("Driver lacks a valid signature chain"); }
                if (score > 0) alerts.Add(new DetectionAlert("driver", Math.Min(score, 100), reasons, ProcessName: name, ExecutablePath: path));
            }
            _initialized = true;
        }
        catch (Exception ex) { context.Logger.WriteAsync("ERROR", $"Driver scan failed: {ex.Message}", cancellationToken).GetAwaiter().GetResult(); }
        return (IReadOnlyList<DetectionAlert>)alerts;
    }, cancellationToken);

    private static string? NormalizeDriverPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var path = value.Trim().Trim('"').Split(' ')[0].Replace("\\SystemRoot", Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase);
        return path;
    }
}
