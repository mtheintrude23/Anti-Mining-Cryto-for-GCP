using System.Diagnostics;
using System.Text.Json;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

public sealed class NetworkInspector : IThreatDetector
{
    public string Name => "network";

    public async Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var alerts = new List<DetectionAlert>();
        try
        {
            const string script = "Get-NetTCPConnection -State Established -ErrorAction Stop | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress";
            var output = await RunPowerShellAsync(script, cancellationToken);
            if (string.IsNullOrWhiteSpace(output)) return alerts;
            using var document = JsonDocument.Parse(output);
            IEnumerable<JsonElement> connections = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray().ToArray()
                : [document.RootElement];
            foreach (var connection in connections)
            {
                var pid = connection.GetProperty("OwningProcess").GetInt32();
                var remoteAddress = connection.GetProperty("RemoteAddress").GetString() ?? string.Empty;
                var remotePort = connection.GetProperty("RemotePort").GetInt32();
                var reasons = new List<string>(); var score = 0;
                if (context.Config.PoolPorts.Contains(remotePort)) { score += 55; reasons.Add($"Mining pool port {remotePort}"); }
                if (context.Config.BlacklistIps.Any(cidr => CidrMatches(remoteAddress, cidr))) { score += 65; reasons.Add($"Blacklisted address {remoteAddress}"); }
                if (score == 0) continue;
                string? name = null; string? path = null;
                try { using var p = Process.GetProcessById(pid); name = p.ProcessName; path = p.MainModule?.FileName; } catch { reasons.Add("Owning process details unavailable"); }
                var local = $"{connection.GetProperty("LocalAddress").GetString()}:{connection.GetProperty("LocalPort").GetInt32()}";
                alerts.Add(new DetectionAlert("network", Math.Min(score, 100), reasons,
                    ProcessId: pid, ProcessName: name, ExecutablePath: path,
                    NetworkContext: $"{local} -> {remoteAddress}:{remotePort}"));
            }
        }
        catch (Exception ex) { await context.Logger.WriteAsync("ERROR", $"Network scan failed: {ex.Message}", cancellationToken); }
        return alerts;
    }

    private static async Task<string> RunPowerShellAsync(string script, CancellationToken token)
    {
        using var process = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -Command \"{script}\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true }) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var output = process.StandardOutput.ReadToEndAsync(token);
        await process.WaitForExitAsync(token);
        if (process.ExitCode != 0) throw new InvalidOperationException(await process.StandardError.ReadToEndAsync(token));
        return await output;
    }

    private static bool CidrMatches(string address, string cidr)
    {
        try
        {
            var parts = cidr.Split('/'); var target = System.Net.IPAddress.Parse(address); var network = System.Net.IPAddress.Parse(parts[0]);
            if (parts.Length == 1) return target.Equals(network);
            var prefix = int.Parse(parts[1]); var a = target.GetAddressBytes(); var b = network.GetAddressBytes();
            if (a.Length != b.Length || prefix < 0 || prefix > a.Length * 8) return false;
            for (var i = 0; i < prefix; i++) if (((a[i / 8] >> (7 - i % 8)) & 1) != ((b[i / 8] >> (7 - i % 8)) & 1)) return false;
            return true;
        }
        catch { return false; }
    }
}
