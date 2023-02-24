namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Specifies the possible asymmetric key material export format.
/// </summary>
public enum KeyPkcsFormat {
    /// <summary>
    /// Key format is unknown or not available.
    /// </summary>
    Unknown,
    /// <summary>
    /// Only key data is exported. No key algorithm identifier is exported.
    /// </summary>
    Pkcs1,
    /// <summary>
    /// Entire key is exported, including key material and key algorithm identifier.
    /// </summary>
    Pkcs8
}