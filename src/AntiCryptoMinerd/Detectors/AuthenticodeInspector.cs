using System.Security.Cryptography.X509Certificates;

namespace AntiCryptoMinerd.Detectors;

public static class AuthenticodeInspector
{
    public static SignatureInfo Inspect(string path)
    {
        try
        {
            var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            using var chain = new X509Chain();
            var chainValid = chain.Build(certificate);
            var microsoft = certificate.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) && chainValid;
            return new SignatureInfo(true, chainValid, microsoft, certificate.Subject);
        }
        catch { return new SignatureInfo(false, false, false, null); }
    }

    public static bool IsMicrosoftSigned(string path) => Inspect(path).MicrosoftSigned;
}

public sealed record SignatureInfo(bool HasSignature, bool ChainValid, bool MicrosoftSigned, string? Publisher);
