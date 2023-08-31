namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains enumeration of certificate enrollment disposition status.
/// </summary>
public enum AdcsRequestStatus {
    /// <summary>
    /// Request did not complete.
    /// </summary>
    Incomplete      = 0,
    /// <summary>
    /// Request failed.
    /// </summary>
    Failed          = 1,
    /// <summary>
    /// Request denied.
    /// </summary>
    Denied          = 2,
    /// <summary>
    /// Request successfully issued.
    /// </summary>
    Issued          = 3,
    /// <summary>
    /// Certificate issued separately.
    /// </summary>
    IssuedOutOfBand = 4,
    /// <summary>
    /// Request taken under submission.
    /// </summary>
    UnderSubmission = 5,
    /// <summary>
    /// Request is revoked.
    /// </summary>
    Revoked         = 6,
}