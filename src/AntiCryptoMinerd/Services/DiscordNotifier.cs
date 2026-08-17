using System.Text;
using System.Text.Json;
using AntiCryptoMinerd.Core;
using AntiCryptoMinerd.Infrastructure;
using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Services;

public sealed class DiscordNotifier
{
    private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(8) };

    public async Task SendAsync(DetectionAlert alert, ScanContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(context.Config.WebhookUrl)) return;
        try
        {
            var gcp = await context.Gcp.GetInstanceAsync(cancellationToken);
            var embed = new
            {
                title = $"AntiCryptoMinerd: {alert.DetectionType}",
                color = alert.Confidence >= 90 ? 15158332 : 16753920,
                timestamp = alert.OccurredAtUtc.ToString("O"),
                fields = new[]
                {
                    Field("Hostname", context.Hostname), Field("GCP instance", gcp is null ? "Not detected" : $"{gcp.ProjectId}/{gcp.Zone}/{gcp.InstanceName}"),
                    Field("Confidence", alert.Confidence.ToString()), Field("Reasons", string.Join("; ", alert.Reasons)),
                    Field("Path / command", Trim($"{alert.ExecutablePath} {alert.CommandLine}")), Field("Network", alert.NetworkContext ?? "None"),
                    Field("Resource", alert.ResourceContext ?? "None"), Field("Action", alert.ActionTaken)
                }
            };
            var payload = JsonSerializer.Serialize(new { embeds = new[] { embed } }, Json.Options);
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var response = await _client.PostAsync(context.Config.WebhookUrl, content, cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        catch (Exception ex) { await context.Logger.WriteAsync("ERROR", $"Discord notification failed: {ex.Message}", cancellationToken); }
    }

    private static object Field(string name, string value) => new { name, value = string.IsNullOrWhiteSpace(value) ? "N/A" : value, inline = false };
    private static string Trim(string value) => value.Length <= 1000 ? value : value[..997] + "...";
}
