using System.Text.Json;
using AntiCryptoMinerd.Infrastructure;

namespace AntiCryptoMinerd.Configuration;

public sealed class ConfigProvider : IDisposable
{
    private readonly object _sync = new();
    private readonly string _path;
    private readonly FileSystemWatcher _watcher;
    private AgentConfig _current;

    public ConfigProvider()
    {
        var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "anti-crypto-minerd");
        Directory.CreateDirectory(dataRoot);
        _path = Environment.GetEnvironmentVariable("ACM_CONFIG_PATH") ?? Path.Combine(dataRoot, "config.json");
        _current = Load();
        _watcher = new FileSystemWatcher(Path.GetDirectoryName(_path)!, Path.GetFileName(_path)) { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName, EnableRaisingEvents = true };
        _watcher.Changed += (_, _) => TryReload();
        _watcher.Created += (_, _) => TryReload();
        _watcher.Renamed += (_, _) => TryReload();
    }

    public AgentConfig Current { get { lock (_sync) return _current; } }
    public event Action? Reloaded;

    private AgentConfig Load()
    {
        if (!File.Exists(_path)) throw new FileNotFoundException($"Configuration file not found: {_path}");
        var config = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(_path), Json.Options) ?? throw new InvalidOperationException("Configuration is empty.");
        config.Validate();
        return config;
    }

    private void TryReload()
    {
        try
        {
            Thread.Sleep(250); // File writers may expose an incomplete document briefly.
            var loaded = Load();
            lock (_sync) _current = loaded;
            Reloaded?.Invoke();
        }
        catch { /* A failed reload retains the last known-good configuration. */ }
    }

    public void Dispose() => _watcher.Dispose();
}
