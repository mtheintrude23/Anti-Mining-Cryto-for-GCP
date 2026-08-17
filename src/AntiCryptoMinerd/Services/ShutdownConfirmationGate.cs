using System.Security.Cryptography;
using AntiCryptoMinerd.Configuration;
using AntiCryptoMinerd.Infrastructure;

namespace AntiCryptoMinerd.Services;

/// <summary>
/// Requires a human with write access to %ProgramData%\anti-crypto-minerd (Administrators/SYSTEM
/// only, per install.ps1's ACLs — ordinary logged-on users cannot write there) to approve a
/// self-shutdown before it happens. This exists because <see cref="Infrastructure.GcpMetadataClient.StopSelfAsync"/>
/// is destructive to a running workload: a confidence-100 false positive should not silently take
/// a production VM offline with no one in the loop.
///
/// Flow:
///  1. On a qualifying alert, generate a one-time numeric code and write it to
///     confirm-shutdown.request (alongside an expiry). The code is also sent through the
///     existing Discord webhook / log / Event Log, so whoever gets paged sees it.
///  2. An Administrator on the box confirms by writing that exact code to
///     confirm-shutdown.approve (e.g. `Set-Content confirm-shutdown.approve -Value <code>`).
///  3. The gate polls for a matching, non-expired approval. No approval within
///     gcp_shutdown_confirm_timeout_seconds means the shutdown is cancelled — fail-safe is
///     "do nothing", not "shut down".
/// Setting gcp_shutdown_require_confirmation=false restores the old immediate-shutdown behavior.
/// </summary>
public sealed class ShutdownConfirmationGate
{
    private readonly string _root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "anti-crypto-minerd");

    public async Task<bool> RequestAndAwaitAsync(AgentConfig config, string reason, SecurityLogger logger, CancellationToken cancellationToken)
    {
        if (!config.GcpShutdownRequireConfirmation) return true;

        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
        var requestPath = Path.Combine(_root, "confirm-shutdown.request");
        var approvePath = Path.Combine(_root, "confirm-shutdown.approve");
        var expires = DateTimeOffset.UtcNow.AddSeconds(config.GcpShutdownConfirmTimeoutSeconds);

        try { if (File.Exists(approvePath)) File.Delete(approvePath); } catch { /* best effort */ }
        await File.WriteAllTextAsync(requestPath, $"{code}\n{expires:O}\n{reason}\n", cancellationToken);
        await logger.WriteAsync("WARN",
            $"Self-shutdown confirmation required (code {code}, expires {expires:O}). An Administrator must run: " +
            $"Set-Content -Path \"{approvePath}\" -Value \"{code}\" within {config.GcpShutdownConfirmTimeoutSeconds}s, or the shutdown is cancelled.",
            cancellationToken);

        while (DateTimeOffset.UtcNow < expires && !cancellationToken.IsCancellationRequested)
        {
            if (TryReadApproval(approvePath) is { } approved && approved == code)
            {
                await logger.WriteAsync("WARN", "Self-shutdown confirmed by administrator.", cancellationToken);
                CleanUp(requestPath, approvePath);
                return true;
            }
            try { await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken); }
            catch (OperationCanceledException) { break; }
        }

        await logger.WriteAsync("WARN", "Self-shutdown NOT confirmed in time; cancelling (VM left running).", cancellationToken);
        CleanUp(requestPath, approvePath);
        return false;
    }

    private static string? TryReadApproval(string approvePath)
    {
        try { return File.Exists(approvePath) ? File.ReadAllText(approvePath).Trim() : null; }
        catch { return null; }
    }

    private static void CleanUp(string requestPath, string approvePath)
    {
        try { if (File.Exists(requestPath)) File.Delete(requestPath); } catch { /* best effort */ }
        try { if (File.Exists(approvePath)) File.Delete(approvePath); } catch { /* best effort */ }
    }
}
