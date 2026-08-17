using System.Net.Http.Headers;
using System.Text.Json;
using AntiCryptoMinerd.Configuration;

namespace AntiCryptoMinerd.Infrastructure;

public sealed class GcpMetadataClient
{
    private static readonly Uri MetadataBase = new("http://metadata.google.internal/computeMetadata/v1/");
    private readonly HttpClient _client = new() { BaseAddress = MetadataBase, Timeout = TimeSpan.FromSeconds(5) };

    public GcpMetadataClient() => _client.DefaultRequestHeaders.Add("Metadata-Flavor", "Google");

    public async Task<GcpInstance?> GetInstanceAsync(CancellationToken cancellationToken)
    {
        try
        {
            var project = await _client.GetStringAsync("project/project-id", cancellationToken);
            var zonePath = await _client.GetStringAsync("instance/zone", cancellationToken);
            var name = await _client.GetStringAsync("instance/name", cancellationToken);
            return new GcpInstance(project.Trim(), zonePath.Trim().Split('/').Last(), name.Trim());
        }
        catch { return null; } // Non-GCE hosts intentionally have no metadata.
    }

    public async Task<bool> StopSelfAsync(AgentConfig config, CancellationToken cancellationToken)
    {
        if (!config.GcpShutdownSelf) return false;
        return await CallInstanceActionAsync(config, "stop", HttpMethod.Post, cancellationToken);
    }

    public async Task<bool> DeleteSelfAsync(AgentConfig config, CancellationToken cancellationToken)
    {
        if (!config.GcpDeleteSelf) return false;
        return await CallInstanceActionAsync(config, string.Empty, HttpMethod.Delete, cancellationToken);
    }

    private async Task<bool> CallInstanceActionAsync(AgentConfig config, string actionSuffix, HttpMethod method, CancellationToken cancellationToken)
    {
        try
        {
            var metadata = await GetInstanceAsync(cancellationToken);
            var project = string.IsNullOrWhiteSpace(config.GcpProjectId) ? metadata?.ProjectId : config.GcpProjectId;
            var zone = string.IsNullOrWhiteSpace(config.GcpZone) ? metadata?.Zone : config.GcpZone;
            var instance = string.IsNullOrWhiteSpace(config.GcpInstanceName) ? metadata?.InstanceName : config.GcpInstanceName;
            if (!GcpIdentifier.IsValidProject(project ?? string.Empty) || !GcpIdentifier.IsValidZone(zone ?? string.Empty) || !GcpIdentifier.IsValidInstance(instance ?? string.Empty)) return false;

            var tokenResponse = await _client.GetStringAsync("instance/service-accounts/default/token", cancellationToken);
            var token = JsonSerializer.Deserialize<TokenResponse>(tokenResponse, Json.Options)?.AccessToken;
            if (string.IsNullOrWhiteSpace(token)) return false;
            using var api = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var url = $"https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}" + (string.IsNullOrEmpty(actionSuffix) ? "" : $"/{actionSuffix}");
            using var request = new HttpRequestMessage(method, url);
            using var response = await api.SendAsync(request, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private sealed record TokenResponse(string AccessToken);
}

public sealed record GcpInstance(string ProjectId, string Zone, string InstanceName);
