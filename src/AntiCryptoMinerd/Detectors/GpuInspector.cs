using System.Diagnostics;
using System.Management;
using System.Text.Json;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

/// <summary>
/// Detects GPU-based crypto mining via two independent signals:
///
///  1. WMI GPU engine performance counters (Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine)
///     Works on any WDDM GPU (NVIDIA, AMD, Intel) on Windows 10/2016+. Samples 3D/Compute
///     engine utilization; sustained high utilisation on the Compute engine is the strongest
///     indicator since legitimate workloads rarely peg Compute at 90%+ for extended periods.
///
///  2. nvidia-smi (if present) — gives per-process GPU utilisation, VRAM usage, temperature,
///     and power draw. Mining rigs typically show: utilisation 85–100%, temp 60–85°C,
///     power near TDP limit, accessed from a non-signed/temp-path process.
///
/// Both signals feed a composite confidence score that is combined with ProcessInspector's
/// name/signature score at the alert level (separate alerts, same remediation pipeline).
/// </summary>
public sealed class GpuInspector : IThreatDetector
{
    public string Name => "gpu";

    // GPU miner command-line / process-name fragments that ProcessInspector might miss if
    // the binary was renamed (here we find them via nvidia-smi's PID→name resolution).
    private static readonly string[] GpuMinerSignatures =
    [
        "xmrig", "t-rex", "trex", "lolminer", "nbminer", "phoenixminer",
        "teamredminer", "gminer", "srbminer", "wildrig", "kawpowminer",
        "ethminer", "bminer", "miniz", "nanominer", "cryptodredge",
        "excavator", "ccminer", "cgminer", "sgminer", "claymore",
        "stratum", "mining", "nicehash"
    ];

    public async Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var alerts = new List<DetectionAlert>();
        try
        {
            var wmiAlerts = await ScanWmiGpuCountersAsync(context, cancellationToken);
            alerts.AddRange(wmiAlerts);
        }
        catch (Exception ex)
        {
            await context.Logger.WriteAsync("DEBUG", $"GPU WMI scan failed: {ex.Message}", cancellationToken);
        }

        try
        {
            var nvAlerts = await ScanNvidiaSmiAsync(context, cancellationToken);
            alerts.AddRange(nvAlerts);
        }
        catch (Exception ex)
        {
            await context.Logger.WriteAsync("DEBUG", $"nvidia-smi scan failed: {ex.Message}", cancellationToken);
        }

        return alerts;
    }

    // ── WMI GPU engine counters ────────────────────────────────────────────────────────────

    private static Task<List<DetectionAlert>> ScanWmiGpuCountersAsync(ScanContext context, CancellationToken cancellationToken) =>
        Task.Run(() =>
        {
            var alerts = new List<DetectionAlert>();

            // Aggregate utilisation per GPU across all engine types.
            var gpuUtil = new Dictionary<string, (double MaxUtil, string EngineType)>(StringComparer.OrdinalIgnoreCase);

            using var searcher = new ManagementObjectSearcher(
                @"root\cimv2",
                "SELECT Name, UtilizationPercentage FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine");

            foreach (ManagementObject obj in searcher.Get())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var name = obj["Name"]?.ToString() ?? "";
                var util = Convert.ToDouble(obj["UtilizationPercentage"] ?? 0);
                if (util < 1) continue;

                // Name format: "luid_0x00000000_0x00013DB7_phys_0_eng_0_engtype_3D"
                // Extract adapter LUID and engine type.
                var engType = ExtractSegment(name, "engtype_");
                var adapterKey = ExtractAdapterKey(name);

                if (!gpuUtil.TryGetValue(adapterKey, out var cur) || util > cur.MaxUtil)
                    gpuUtil[adapterKey] = (util, engType);
            }

            foreach (var (adapter, (maxUtil, engType)) in gpuUtil)
            {
                var score = 0;
                var reasons = new List<string>();

                // Compute engine at high util is very suspicious — legitimate apps rarely
                // saturate Compute (GPGPU) for extended periods except miners and ML training.
                // 3D engine at 95%+ can also indicate mining (e.g. XMRig Monero via OpenGL).
                if (engType.Equals("Compute", StringComparison.OrdinalIgnoreCase) && maxUtil >= 80)
                {
                    score += 50;
                    reasons.Add($"GPU Compute engine utilisation {maxUtil:F0}% (adapter {adapter})");
                }
                else if (maxUtil >= 95)
                {
                    score += 30;
                    reasons.Add($"GPU {engType} engine utilisation {maxUtil:F0}% (adapter {adapter})");
                }
                else if (maxUtil >= 80)
                {
                    score += 10;
                    reasons.Add($"GPU {engType} engine utilisation {maxUtil:F0}% (adapter {adapter})");
                }

                if (score > 0)
                    alerts.Add(new DetectionAlert("gpu-wmi", Math.Min(score, 100), reasons));
            }

            return alerts;
        }, cancellationToken);

    private static string ExtractSegment(string name, string prefix)
    {
        var idx = name.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        return idx < 0 ? "Unknown" : name[(idx + prefix.Length)..].Split('_')[0];
    }

    private static string ExtractAdapterKey(string name)
    {
        // "luid_0x00000000_0x00013DB7_phys_0_..."  → "0x00000000_0x00013DB7"
        const string luid = "luid_";
        var idx = name.IndexOf(luid, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return name;
        var rest = name[(idx + luid.Length)..];
        var parts = rest.Split('_');
        return parts.Length >= 2 ? $"{parts[0]}_{parts[1]}" : rest;
    }

    // ── nvidia-smi ────────────────────────────────────────────────────────────────────────

    private static readonly string[] NvidiaSmiPaths =
    [
        @"C:\Windows\System32\nvidia-smi.exe",
        @"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        @"C:\Windows\SysWOW64\nvidia-smi.exe",
    ];

    private static async Task<List<DetectionAlert>> ScanNvidiaSmiAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var smiPath = NvidiaSmiPaths.FirstOrDefault(File.Exists);
        if (smiPath is null) return [];

        var alerts = new List<DetectionAlert>();

        // Query 1: per-GPU summary (utilization, temperature, power)
        var gpuQuery = await RunNvidiaSmiAsync(smiPath,
            "--query-gpu=index,utilization.gpu,utilization.memory,temperature.gpu,power.draw,power.limit,name",
            "--format=csv,noheader,nounits", cancellationToken);

        foreach (var line in gpuQuery.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split(',', StringSplitOptions.TrimEntries);
            if (parts.Length < 7) continue;
            if (!int.TryParse(parts[0], out var idx)) continue;
            if (!double.TryParse(parts[1], out var gpuUtil)) continue;
            if (!double.TryParse(parts[3], out var temp)) continue;
            double.TryParse(parts[4], out var powerDraw);
            double.TryParse(parts[5], out var powerLimit);
            var gpuName = parts[6];

            var score = 0;
            var reasons = new List<string>();

            if (gpuUtil >= 85) { score += 40; reasons.Add($"GPU#{idx} ({gpuName}) utilisation {gpuUtil:F0}%"); }
            else if (gpuUtil >= 70) { score += 20; reasons.Add($"GPU#{idx} ({gpuName}) utilisation {gpuUtil:F0}%"); }

            if (temp >= 75) { score += 10; reasons.Add($"GPU#{idx} temperature {temp:F0}°C"); }

            if (powerLimit > 0 && powerDraw / powerLimit >= 0.90)
            { score += 15; reasons.Add($"GPU#{idx} power {powerDraw:F0}W / {powerLimit:F0}W limit ({powerDraw / powerLimit * 100:F0}%)"); }

            if (score > 0)
                alerts.Add(new DetectionAlert("gpu-nvidia", Math.Min(score, 100), reasons));
        }

        // Query 2: per-compute-process (PID + GPU memory usage)
        var procQuery = await RunNvidiaSmiAsync(smiPath,
            "--query-compute-apps=pid,used_memory,gpu_uuid",
            "--format=csv,noheader,nounits", cancellationToken);

        foreach (var line in procQuery.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split(',', StringSplitOptions.TrimEntries);
            if (parts.Length < 2) continue;
            if (!int.TryParse(parts[0], out var pid)) continue;
            double.TryParse(parts[1], out var vramMb);

            var (procName, procPath, cmdLine) = GetProcessInfo(pid);
            if (procName is null) continue;

            var reasons = new List<string>();
            var score = 0;

            var haystack = $"{procName} {procPath} {cmdLine}";
            var matched = GpuMinerSignatures.Where(s => haystack.Contains(s, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matched.Length > 0) { score += 60; reasons.Add($"GPU process signature: {string.Join(", ", matched)}"); }

            if (vramMb >= 200) { score += 10; reasons.Add($"GPU VRAM usage {vramMb:F0} MB"); }

            if (procPath is not null && IsSuspiciousPath(procPath, out var pathReason))
            { score += 20; reasons.Add(pathReason); }

            if (score > 0)
                alerts.Add(new DetectionAlert("gpu-process", Math.Min(score, 100), reasons, pid, procName, null, procPath, cmdLine));
        }

        return alerts;
    }

    private static async Task<string> RunNvidiaSmiAsync(string smiPath, string args1, string args2, CancellationToken cancellationToken)
    {
        using var proc = new Process();
        proc.StartInfo = new ProcessStartInfo(smiPath, $"{args1} {args2}")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        proc.Start();
        var output = await proc.StandardOutput.ReadToEndAsync(cancellationToken);
        await proc.WaitForExitAsync(cancellationToken);
        return output;
    }

    private static (string? Name, string? Path, string? Cmd) GetProcessInfo(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId={pid}");
            foreach (ManagementObject obj in searcher.Get())
                return (obj["Name"]?.ToString(), obj["ExecutablePath"]?.ToString(), obj["CommandLine"]?.ToString());
        }
        catch { }
        return (null, null, null);
    }

    private static bool IsSuspiciousPath(string path, out string reason)
    {
        var temp = System.IO.Path.GetTempPath();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (path.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) { reason = "GPU process launched from Temp"; return true; }
        if (path.StartsWith(appData, StringComparison.OrdinalIgnoreCase)) { reason = "GPU process launched from AppData"; return true; }
        if (path.Any(c => c > 127)) { reason = "Path contains non-ASCII characters"; return true; }
        reason = string.Empty; return false;
    }
}
