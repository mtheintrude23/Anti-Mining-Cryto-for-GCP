using System.Security.Cryptography;
using System.Text;

namespace AntiCryptoMinerd.Infrastructure;

/// <summary>
/// Encrypts/decrypts secrets (e.g. webhook URLs) at rest using Windows DPAPI, scoped to the
/// local machine. A file containing only the encrypted blob is useless if copied to another
/// host or read by a user who is not an Administrator/SYSTEM on this machine, because DPAPI
/// machine-scope keys never leave the machine's DPAPI key store.
///
/// This is NOT a substitute for restrictive ACLs on config.json — it is defense in depth for
/// the case where the file is read despite ACLs (backup, misconfiguration, etc.).
/// </summary>
public static class SecretProtector
{
    // Fixed, non-secret "purpose" bytes. This does not add real secrecy (it ships in the
    // binary), but it domain-separates this app's DPAPI blobs from other apps' blobs and
    // prevents accidental cross-use of ciphertext.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AntiCryptoMinerd.Config.v1");

    public const string Prefix = "dpapi:";

    public static bool IsProtected(string? value) => !string.IsNullOrEmpty(value) && value.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>Encrypts plaintext for storage in config.json, returning a "dpapi:&lt;base64&gt;" string.</summary>
    public static string Protect(string plaintext)
    {
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var encrypted = ProtectedData.Protect(bytes, Entropy, DataProtectionScope.LocalMachine);
        return Prefix + Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Resolves a config value that may be either plaintext (legacy) or a "dpapi:" blob.
    /// Returns empty string, and never throws, on malformed/undecryptable input so a bad
    /// value degrades to "no webhook configured" rather than crashing the service.
    /// </summary>
    public static string Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        if (!IsProtected(value)) return value; // legacy plaintext, unchanged

        try
        {
            var encrypted = Convert.FromBase64String(value[Prefix.Length..]);
            var decrypted = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(decrypted);
        }
        catch
        {
            return string.Empty;
        }
    }
}
