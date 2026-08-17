using System.Management;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

public sealed class ProcessInspector : IThreatDetector
{
    private static readonly string[] Signatures = ["xmrig", "xmrig-proxy", "nanominer", "t-rex", "trex", "bminer", "nbminer", "lolminer", "phoenixminer", "teamredminer", "cpuminer", "minerd", "ethminer", "kawpowminer", "cryptonight", "stratum+tcp", "mining.subscribe", "srbminer", "gminer", "wildrig"];
    public string Name => "processes";

    public Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken) => Task.Run(() =>
    {
        var alerts = new List<DetectionAlert>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process");
            foreach (ManagementObject process in searcher.Get())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var pid = Convert.ToInt32(process["ProcessId"] ?? 0);
                var name = process["Name"]?.ToString() ?? "unknown";
                var path = process["ExecutablePath"]?.ToString();
                var commandLine = process["CommandLine"]?.ToString() ?? string.Empty;
                if (IsAllowlisted(context, name, path, null)) continue;

                var reasons = new List<string>();
                var score = 0;
                var haystack = $"{name} {path} {commandLine}";
                var matched = Signatures.Where(s => haystack.Contains(s, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (matched.Length > 0) { score += 55; reasons.Add($"Miner signature: {string.Join(", ", matched)}"); }
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { if (score > 0) { score += 5; reasons.Add("Executable path unavailable"); } }
                else
                {
                    if (IsSuspiciousPath(path, out var pathReason)) { score += 20; reasons.Add(pathReason); }
                    var signature = AuthenticodeInspector.Inspect(path);
                    if (signature.MicrosoftSigned) continue; // Valid Microsoft binaries are never alerted or remediated.
                    if (IsAllowlisted(context, name, path, signature.Publisher)) continue;
                    if (!signature.ChainValid && (matched.Length > 0 || reasons.Count > 0)) { score += 15; reasons.Add("No valid Authenticode chain"); }
                    var entropy = ShannonEntropy(path, context.Config.EntropySampleBytes);
                    if (entropy > context.Config.EntropyThreshold) { score += 20; reasons.Add($"High executable entropy: {entropy:F2}"); }
                }
                if (score > 0) alerts.Add(new DetectionAlert("process", Math.Min(score, 100), reasons, pid, name, path, commandLine));
            }
        }
        catch (Exception ex) { context.Logger.WriteAsync("ERROR", $"WMI process scan failed: {ex.Message}", cancellationToken).GetAwaiter().GetResult(); }
        return (IReadOnlyList<DetectionAlert>)alerts;
    }, cancellationToken);

    private static bool IsAllowlisted(ScanContext context, string name, string? path, string? publisher) => context.Config.Allowlist.Any(item =>
        string.Equals(item, name, StringComparison.OrdinalIgnoreCase) ||
        (!string.IsNullOrWhiteSpace(path) && path.Contains(item, StringComparison.OrdinalIgnoreCase)) ||
        (!string.IsNullOrWhiteSpace(publisher) && publisher.Contains(item, StringComparison.OrdinalIgnoreCase)));

    private static bool IsSuspiciousPath(string path, out string reason)
    {
        var temp = Path.GetTempPath();
        var localTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (path.StartsWith(temp, StringComparison.OrdinalIgnoreCase) || path.StartsWith(localTemp, StringComparison.OrdinalIgnoreCase)) { reason = "Executable launched from Temp"; return true; }
        if (path.StartsWith(appData, StringComparison.OrdinalIgnoreCase)) { reason = "Executable launched from AppData"; return true; }
        try { if ((File.GetAttributes(path) & FileAttributes.Hidden) != 0) { reason = "Hidden executable"; return true; } } catch { }
        if (path.Any(c => c > 127)) { reason = "Path contains non-ASCII characters"; return true; }
        reason = string.Empty; return false;
    }

    private static double ShannonEntropy(string path, int sampleSize)
    {
        try
        {
            var counts = new int[256]; var total = 0;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buffer = new byte[Math.Min(sampleSize, 65536)];
            while (total < sampleSize)
            {
                var read = stream.Read(buffer, 0, Math.Min(buffer.Length, sampleSize - total));
                if (read == 0) break;
                for (var i = 0; i < read; i++) counts[buffer[i]]++;
                total += read;
            }
            if (total == 0) return 0;
            return -counts.Where(c => c > 0).Sum(c => { var p = (double)c / total; return p * Math.Log2(p); });
        }
        catch { return 0; }
    }
}
