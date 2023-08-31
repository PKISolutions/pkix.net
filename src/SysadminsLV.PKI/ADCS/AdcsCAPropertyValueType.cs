namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains possible data types to store the data in Certification Authority database and configuration.
/// </summary>
public enum AdcsCAPropertyValueType {
    /// <summary>
    /// Signed long data.
    /// </summary>
    Long     = 1,
    /// <summary>
    /// Date/time.
    /// </summary>
    DateTime = 2,
    /// <summary>
    /// Binary data.
    /// </summary>
    Binary   = 3,
    /// <summary>
    /// Unicode string data.
    /// </summary>
    String   = 4
}