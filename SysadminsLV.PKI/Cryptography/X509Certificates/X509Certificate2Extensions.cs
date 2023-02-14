using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains extension methods for <see cref="X509Certificate2"/> objects.
/// </summary>
public static class X509Certificate2Extensions {
    #region Format

    /// <summary>
    /// Displays an X.509 certificate dump.
    /// </summary>
    /// <returns>Formatted string.</returns>
    public static String Format(this X509Certificate2 cert) {
        if (cert == null) {
            return String.Empty;
        }

        var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
        String sigValue = AsnFormatter.BinaryToString(blob.Signature.Value.Reverse().ToArray(), EncodingType.HexAddress)
            .Replace(Environment.NewLine, Environment.NewLine + "    ");
        var sb = new StringBuilder();


        sb.Append($@"X509 Certificate:
Version: {cert.Version} (0x{cert.Version - 1:x})
Serial Number: {cert.SerialNumber}

{blob.SignatureAlgorithm}
Issuer:
    {cert.IssuerName.FormatReverse(true).Replace(Environment.NewLine, Environment.NewLine + "    ")}
  Name Hash(md5)    : {getNameHash(cert.IssuerName, MD5.Create())}
  Name Hash(sha1)   : {getNameHash(cert.IssuerName, SHA1.Create())}
  Name Hash(sha256) : {getNameHash(cert.IssuerName, SHA256.Create())}

Valid From: {cert.NotBefore}
Valid To  : {cert.NotAfter}

Subject:
    {cert.SubjectName.FormatReverse(true).Replace(Environment.NewLine, Environment.NewLine + "    ")}
  Name Hash(md5)    : {getNameHash(cert.SubjectName, MD5.Create())}
  Name Hash(sha1)   : {getNameHash(cert.SubjectName, SHA1.Create())}
  Name Hash(sha256) : {getNameHash(cert.SubjectName, SHA256.Create())}

{cert.PublicKey.Format().TrimEnd()}

Certificate Extensions: {cert.Extensions.Count}
{cert.Extensions.Format()}

{blob.SignatureAlgorithm.ToString().TrimEnd()}
Signature: UnusedBits={blob.Signature.UnusedBits}
    {sigValue}
");
        sb.AppendLine(cert.Issuer.Equals(cert.Subject, StringComparison.InvariantCultureIgnoreCase)
            ? "Root Certificate: Subject matches Issuer"
            : "Non-root Certificate");
        sb.AppendLine($"Key Id Hash(sha1)       : {getHashData(cert.PublicKey.Encode(), SHA1.Create())}");
        sb.AppendLine($"Key Id Hash(rfc-md5)    : {getHashData(cert.PublicKey.EncodedKeyValue.RawData, MD5.Create())}");
        sb.AppendLine($"Key Id Hash(rfc-sha1)   : {getHashData(cert.PublicKey.EncodedKeyValue.RawData, SHA1.Create())}");
        sb.AppendLine($"Key Id Hash(rfc-sha256) : {getHashData(cert.PublicKey.EncodedKeyValue.RawData, SHA256.Create())}");
        sb.AppendLine($"Key Id Hash(pin-sha256-b64) : {getKeyPinHash(cert.PublicKey, SHA256.Create())}");
        sb.AppendLine($"Key Id Hash(pin-sha256-hex) : {getHashData(cert.PublicKey.Encode(), SHA256.Create())}");
        sb.AppendLine($"Cert Hash(md5)    : {getCertHash(cert, MD5.Create())}");
        sb.AppendLine($"Cert Hash(sha1)   : {getCertHash(cert, SHA1.Create())}");
        sb.AppendLine($"Cert Hash(sha256) : {getCertHash(cert, SHA256.Create())}");
        sb.AppendLine($"Signature Hash    : {getHashData(blob.GetRawSignature(), SHA1.Create())}");
        return sb.ToString();
    }
    static String getCertHash(X509Certificate2 cert, HashAlgorithm hasher) {
        return getHashData(cert.RawData, hasher);
    }
    static String getNameHash(AsnEncodedData name, HashAlgorithm hasher) {
        return getHashData(name.RawData, hasher);
    }
    static String getHashData(Byte[] rawData, HashAlgorithm hasher) {
        StringBuilder sb = new StringBuilder();
        using (hasher) {
            foreach (Byte b in hasher.ComputeHash(rawData)) {
                sb.Append($"{b:x2}");
            }
        }

        return sb.ToString();
    }
    static String getKeyPinHash(PublicKey key, HashAlgorithm hasher) {
        using (hasher) {
            return Convert.ToBase64String(hasher.ComputeHash(key.Encode()));
        }
    }

    #endregion
}
