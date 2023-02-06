namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

/// <summary>
/// The X509PolicyQualifierType enumeration type specifies the type of qualifier applied to a certificate policy
/// </summary>
public enum X509PolicyQualifierType {
    /// <summary>
    /// The qualifier type is not specified.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The qualifier is a URL that points to a Certification Practice Statement (CPS) that has been defined
    ///  by the certification authority to outline the policies under which the certificate was issued and the
    ///  purposes for which the certificate can be used.
    /// </summary>
    CpsUrl = 1,
    /// <summary>
    /// The qualifier is a text statement to be displayed by the application to any user who relies on the certificate.
    /// The user notice identifies the permitted uses of the certificate.
    /// </summary>
    UserNotice = 2
}