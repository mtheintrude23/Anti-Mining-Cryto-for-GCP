using System.Diagnostics;
using System.Text;

namespace AntiCryptoMinerd.Infrastructure;

public sealed class SecurityLogger
{
    private const string Source = "AntiCryptoMinerd";
    private readonly string _logPath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public SecurityLogger()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "anti-crypto-minerd", "logs");
        Directory.CreateDirectory(root);
        _logPath = Path.Combine(root, "anti-crypto-minerd.log");
        try { if (!EventLog.SourceExists(Source)) EventLog.CreateEventSource(Source, "Application"); } catch { /* Creating an event source needs elevation. */ }
    }

    public async Task WriteAsync(string level, string message, CancellationToken cancellationToken = default)
    {
        var line = $"{DateTimeOffset.UtcNow:O} [{level}] {message}{Environment.NewLine}";
        await _lock.WaitAsync(cancellationToken);
        try { await File.AppendAllTextAsync(_logPath, line, Encoding.UTF8, cancellationToken); }
        catch { /* Logging must never terminate the service. */ }
        finally { _lock.Release(); }

        try { EventLog.WriteEntry(Source, message, level is "ERROR" ? EventLogEntryType.Error : EventLogEntryType.Information); }
        catch { /* File logging is retained when Event Log access is unavailable. */ }
    }
}
