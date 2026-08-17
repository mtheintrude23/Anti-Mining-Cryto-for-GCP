using Microsoft.Win32;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Detectors;

public sealed class PersistenceMonitor : IThreatDetector, IDisposable
{
    private readonly Dictionary<string, string> _previous = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<DetectionAlert> _fileEvents = new();
    private readonly List<FileSystemWatcher> _watchers = [];
    private bool _initialized;
    public string Name => "persistence";

    public PersistenceMonitor()
    {
        WatchStartup(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup)));
        WatchStartup(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)));
    }

    public async Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken)
    {
        var alerts = new List<DetectionAlert>();
        while (_fileEvents.TryDequeue(out var alert)) alerts.Add(alert);
        try
        {
            var snapshot = SnapshotRegistry();
            foreach (var pair in snapshot)
            {
                if (_initialized && (!_previous.TryGetValue(pair.Key, out var old) || old != pair.Value))
                    alerts.Add(new DetectionAlert("persistence", 75, ["Registry persistence changed"], ResourceContext: $"{pair.Key} = {pair.Value}"));
            }
            _previous.Clear(); foreach (var pair in snapshot) _previous[pair.Key] = pair.Value;
            foreach (var task in await SnapshotTasksAsync(cancellationToken))
            {
                var key = $"task:{task.Key}";
                if (_initialized && (!_previous.TryGetValue(key, out var old) || old != task.Value)) alerts.Add(new DetectionAlert("persistence", 70, ["Scheduled task created or modified"], ResourceContext: task.Key));
                _previous[key] = task.Value;
            }
            _initialized = true;
        }
        catch (Exception ex) { await context.Logger.WriteAsync("ERROR", $"Persistence scan failed: {ex.Message}", cancellationToken); }
        return alerts;
    }

    private void WatchStartup(string path)
    {
        try
        {
            if (!Directory.Exists(path)) return;
            var watcher = new FileSystemWatcher(path) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime, EnableRaisingEvents = true };
            FileSystemEventHandler handler = (_, e) => _fileEvents.Enqueue(new DetectionAlert("persistence", 70, [$"Startup file {e.ChangeType}"], ExecutablePath: e.FullPath, ResourceContext: e.FullPath));
            watcher.Created += handler; watcher.Changed += handler; watcher.Renamed += (_, e) => handler(_, e); _watchers.Add(watcher);
        }
        catch { /* Startup monitoring remains best-effort. */ }
    }

    private static Dictionary<string, string> SnapshotRegistry()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var locations = new[]
        {
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"), (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"), (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
        };
        foreach (var (hive, path) in locations)
        {
            try
            {
                using var key = hive.OpenSubKey(path); if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    if (path.EndsWith("Winlogon", StringComparison.OrdinalIgnoreCase) && name is not ("Shell" or "Userinit")) continue;
                    result[$"{hive.Name}\\{path}::{name}"] = key.GetValue(name)?.ToString() ?? string.Empty;
                }
            }
            catch { /* One inaccessible key should not block all persistence checks. */ }
        }
        try { using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"); if (services is not null) foreach (var name in services.GetSubKeyNames()) result[$"service:{name}"] = name; } catch { }
        return result;
    }

    private static async Task<Dictionary<string, string>> SnapshotTasksAsync(CancellationToken token)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", "/query /fo csv /v") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });
            if (p is null) return result;
            var output = await p.StandardOutput.ReadToEndAsync(token); await p.WaitForExitAsync(token);
            foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).Skip(1)) result[line] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(line)));
        }
        catch { }
        return result;
    }

    public void Dispose() { foreach (var watcher in _watchers) watcher.Dispose(); }
}
