namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains enumeration values for Certification Authority type.
/// </summary>
public enum AdcsPropCaType {
    /// <summary>
    /// The CA is an enterprise root (self-signed) CA.
    /// </summary>
    EnterpriseRoot        = 0,
    /// <summary>
    /// The CA is an enterprise subordinate CA.
    /// </summary>
    EnterpriseSubordinate = 1,
    /// <summary>
    /// The CA is a stand-alone root (self-signed) CA.
    /// </summary>
    StandaloneRoot        = 3,
    /// <summary>
    /// The CA is a stand-alone subordinate CA.
    /// </summary>
    StandaloneSubordinate = 4,
    /// <summary>
    /// The CA type is unknown.
    /// </summary>
    Unknown               = 5
}