using AntiCryptoMinerd.Models;

namespace AntiCryptoMinerd.Core;

public interface IThreatDetector
{
    string Name { get; }
    Task<IReadOnlyList<DetectionAlert>> ScanAsync(ScanContext context, CancellationToken cancellationToken);
}
