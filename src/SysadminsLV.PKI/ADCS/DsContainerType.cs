namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains enumeration of Active Directory PKI-related containers.
/// </summary>
public enum DsContainerType {
    /// <summary>
    /// Contains certificates of CAs that are allowed to issue client authentication certificates and perform
    /// client private key archival. These certificates are downloaded and cached on Active Directory forest
    /// clients.
    /// </summary>
    NTAuth,
    /// <summary>
    /// Contains CA certificates and cross-certificates that are used by certificate clients to build certificate
    /// chains. These certificates are downloaded and cached on Active Directory forest clients.
    /// </summary>
    AIA,
    /// <summary>
    /// Contains certificate revocation lists published to Active Directory. These CRLs are not automatically
    /// downloaded by clients. They are accessed only when explicit request to specific CRL is created.
    /// </summary>
    CDP,
    /// <summary>
    /// Contains certificates of trusted root CAs approved by Active Directory administrators.
    /// These certificates are downloaded and cached on Active Directory forest clients.
    /// </summary>
    RootCA,
    /// <summary>
    /// Contains enrollment service objects (typically Enterprise CAs) that can be used by clients
    /// that implement [MS-WCCE] communication protocol to manually, or automatically request certificates.
    /// </summary>
    EnrollmentServices,
    /// <summary>
    /// Contains a collection of key recovery agent (KRA) certificates published to Active Directory.
    /// Certification Authorities use this container to locate KRA certificates when key archival is configured.
    /// </summary>
    KRA,
    /// <summary>
    /// Contains a collection of mapping objects between object identifier (OID) and their friendly names.
    /// </summary>
    OID,
    /// <summary>
    /// Contains a collection of certificate templates.
    /// </summary>
    CertificateTemplates
}