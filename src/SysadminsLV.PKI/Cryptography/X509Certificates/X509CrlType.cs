namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

/// <summary>
/// Represents certificate revocation list types.
/// </summary>
public enum X509CrlType {
    /// <summary>
    /// Base CRL.
    /// </summary>
    BaseCrl,
    /// <summary>
    /// Delta or differential CRL.
    /// </summary>
    DeltaCrl
}