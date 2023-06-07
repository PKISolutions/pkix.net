namespace SysadminsLV.PKI.Dcom;
/// <summary>
/// Contains enumeration values of ADCS Certification Authority database tables.
/// </summary>
public enum AdcsDbCRTable {
    /// <summary>
    /// The table of pending requests, denied requests, issued certificates, and revoked certificates.
    /// </summary>
    Request   = 0x0,
    /// <summary>
    /// Contains certificate extensions associated with particular request.
    /// </summary>
    Extension = 0x3000,
    /// <summary>
    /// Contains certificate attributes passed among wth particular request.
    /// </summary>
    Attribute = 0x4000,
    /// <summary>
    /// Contains Certificate Revocation List (CRL) issued by the CA during it's lifetime.
    /// </summary>
    CRL       = 0x5000
}