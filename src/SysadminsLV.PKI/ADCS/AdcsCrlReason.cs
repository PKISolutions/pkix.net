namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Represents a set of possible revocation reasons.
/// </summary>
public enum AdcsCrlReason {
    /// <summary>
    /// Revocation reason is not specified.
    /// </summary>
    Unspecified        = 0,
    /// <summary>
    /// Certificate holder's private key is compromised.
    /// </summary>
    KeyCompromise      = 1,
    /// <summary>
    /// Certification Authority's private key is compromised.
    /// </summary>
    CaCompromise       = 2,
    /// <summary>
    /// 
    /// </summary>
    AffiliationChanged = 3,
    /// <summary>
    /// The certificate is replaced with another certificate and key.
    /// </summary>
    Superseded         = 4,
    /// <summary>
    /// Service is no longer provided.
    /// </summary>
    CeaseOfOperation   = 5,
    /// <summary>
    /// Certificate is temporarily put to CRL with a possibility to unrevoke it later.
    /// </summary>
    CertificateHold    = 6,
    /// <summary>
    /// Removes certificate from CRL. This is possible only if certificate was revoked with <strong>CertificateHold</strong> reason.
    /// </summary>
    RemoveFromCrl      = 8
}