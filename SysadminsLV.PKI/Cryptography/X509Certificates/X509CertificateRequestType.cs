namespace System.Security.Cryptography.X509CertificateRequests;

/// <summary>
/// Defines certificate request formats. Currently only PKCS10 and CMC formats are defined.
/// </summary>
public enum X509CertificateRequestType {
    /// <summary>
    /// The request format is not recognized.
    /// </summary>
    Invalid,
    /// <summary>
    /// Request format is signed PKCS7 message.
    /// </summary>
    PKCS7,
    /// <summary>
    /// Request format is signed PKCS10 message.
    /// </summary>
    PKCS10,
}