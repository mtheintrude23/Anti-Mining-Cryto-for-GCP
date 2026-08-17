using System.Diagnostics;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Detectors;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Services;

public sealed class RemediationEngine
{
    public async Task ApplyAsync(DetectionAlert alert, ScanContext context, CancellationToken cancellationToken)
    {
        if (!context.Config.EnableRemediation || alert.ProcessId is null || string.IsNullOrWhiteSpace(alert.ExecutablePath)) return;
        if (!IsSafeToRemediate(alert.ExecutablePath)) { alert.ActionTaken = "Skipped: protected Microsoft or Windows binary"; return; }
        if (context.Config.DryRun) { alert.ActionTaken = "Dry run: remediation skipped"; return; }

        try
        {
            Process.GetProcessById(alert.ProcessId.Value).Kill(entireProcessTree: true);
            await context.Logger.WriteAsync("WARN", $"Terminated PID {alert.ProcessId} ({alert.ExecutablePath}).", cancellationToken);
        }
        catch (Exception ex) { alert.ActionTaken = $"Terminate failed: {ex.Message}"; return; }

        try
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "anti-crypto-minerd", "quarantine");
            Directory.CreateDirectory(root);
            var destination = Path.Combine(root, $"{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}_pid{alert.ProcessId}_{Path.GetFileName(alert.ExecutablePath)}");
            File.Move(alert.ExecutablePath, destination);
            RunIcacls(destination);
            alert.ActionTaken = $"Terminated and quarantined: {destination}";
        }
        catch (Exception ex) { alert.ActionTaken = $"Terminated; quarantine failed: {ex.Message}"; }
    }

    private static bool IsSafeToRemediate(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (full.StartsWith(Path.Combine(windows, "System32"), StringComparison.OrdinalIgnoreCase) || full.StartsWith(Path.Combine(windows, "SysWOW64"), StringComparison.OrdinalIgnoreCase)) return false;
            return !AuthenticodeInspector.IsMicrosoftSigned(full);
        }
        catch { return false; }
    }

    private static void RunIcacls(string path)
    {
        using var process = Process.Start(new ProcessStartInfo("icacls.exe", $"\"{path}\" /inheritance:r /remove \"Everyone\" \"Users\" \"Authenticated Users\"") { UseShellExecute = false, CreateNoWindow = true });
        process?.WaitForExit(5000);
    }
}
