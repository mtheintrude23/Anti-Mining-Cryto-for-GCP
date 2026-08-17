using System.Diagnostics;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

public sealed class ContainerInspector : IThreatDetector
{
    private int? _baseline;
    public string Name => "containers";

    public async Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("docker.exe", "ps --format {{.ID}}") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });
            if (process is null) return [];
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken); await process.WaitForExitAsync(cancellationToken);
            if (process.ExitCode != 0) return []; // Docker/WSL is optional.
            var count = output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).Length;
            if (_baseline is null) { _baseline = count; return []; }
            var delta = count - _baseline.Value; _baseline = Math.Max(_baseline.Value, count);
            return delta >= 3 ? [new DetectionAlert("container", 65, [$"Container count increased by {delta}"], ResourceContext: $"running={count}"))] : [];
        }
        catch { return []; }
    }
}
