using System;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;

/// <summary>
/// Represents certificate policy 
/// </summary>
public interface ICertificateTemplateCertificatePolicy {
    /// <summary>
    /// Gets certificate policy object identifier string.
    /// </summary>
    String PolicyID { get; }
    /// <summary>
    /// Gets certificate policy (CP and CPS) documentation location uri.
    /// </summary>
    Uri PolicyLocation { get; }
}