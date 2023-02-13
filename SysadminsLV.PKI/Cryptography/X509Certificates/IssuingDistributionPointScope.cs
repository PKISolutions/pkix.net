namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents an X.509 Issuing Distribution Point scope. Only one of choice values can be enabled in IDP extension.
/// </summary>
public enum IssuingDistributionPointScope {
    /// <summary>
    /// No choice is selected.
    /// </summary>
    None               = 0,
    /// <summary>
    /// CRL contains only User certificates. 
    /// </summary>
    OnlyUserCerts      = 1,
    /// <summary>
    /// CRL contains only CA certificates.
    /// </summary>
    OnlyCaCerts        = 2,
    /// <summary>
    /// CRL contains only Attribute certificates.
    /// </summary>
    OnlyAttributeCerts = 5
}