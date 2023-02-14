namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents possible values that identify the status of Time-Stamp request on Time-Stamp Authority (TSA)
/// </summary>
public enum TspResponseStatus {
    /// <summary>
    /// Response has valid confirmations and response contains requested token.
    /// </summary>
    Granted = 0,
    /// <summary>
    /// Response has valid confirmations, but response contains requested token with modifications.
    /// </summary>
    GrantedWithModifications,
    /// <summary>
    /// Request was rejected and no token is included in response.
    /// </summary>
    Rejected,
    /// <summary>
    /// Server is busy and no token is included in response.
    /// </summary>
    Waiting,
    /// <summary>
    /// Revocation is imminent and no token is included in response.
    /// </summary>
    RevocationWarning,
    /// <summary>
    /// Revoked and no token is included in response.
    /// </summary>
    RevocationNotification
}