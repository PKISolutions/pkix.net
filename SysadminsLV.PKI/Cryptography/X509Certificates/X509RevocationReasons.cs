namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

/// <summary>
/// Represents certificate revocation reasons.
/// </summary>
public enum X509RevocationReasons {
    /// <summary>
    /// The reason is not specified.
    /// </summary>
    Unspecified = 0,
    /// <summary>
    /// Private key is compromised.
    /// </summary>
    KeyCompromise = 1,
    /// <summary>
    /// Issuing CA certificate is compromised.
    /// </summary>
    CACompromise = 2,
    /// <summary>
    /// Certificate holder changed its affiliation.
    /// </summary>
    ChangeOfAffiliation = 3,
    /// <summary>
    /// Certificate is superseded by a new certificate.
    /// </summary>
    Superseded = 4,
    /// <summary>
    /// Certificate holder is decommissioned or retired.
    /// </summary>
    CeaseOfOperation = 5,
    /// <summary>
    /// Certificate is revoked temporarily.
    /// </summary>
    CertificateHold = 6,
    /// <summary>
    /// Certificate holder no longer have permissions to use certificate.
    /// </summary>
    PrivilegeWithdrawn = 7,
    /// <summary>
    /// Certificate is removed from CRL.
    /// </summary>
    ReleaseFromHold = 8,
    /// <summary>
    /// Authorization Authority is compromised.
    /// </summary>
    AACompromise = 10,
}