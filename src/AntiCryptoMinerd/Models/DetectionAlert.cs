namespace AntiCryptoMinerd.Models;

public sealed record DetectionAlert(
    string DetectionType,
    int Confidence,
    IReadOnlyList<string> Reasons,
    int? ProcessId = null,
    string? ProcessName = null,
    string? ProcessOwner = null,
    string? ExecutablePath = null,
    string? CommandLine = null,
    string? NetworkContext = null,
    string? ResourceContext = null,
    DateTimeOffset? TimestampUtc = null)
{
    public DateTimeOffset OccurredAtUtc { get; init; } = TimestampUtc ?? DateTimeOffset.UtcNow;
    public string ActionTaken { get; set; } = "Alert only";
}
