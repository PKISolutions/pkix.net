namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Contains extended error information about Time-Stamp Request failure.
/// </summary>
public enum TspFailureStatus {
    /// <summary>
    /// No error.
    /// </summary>
    None                = 0,
    /// <summary>
    /// TSA do not recognize request algorithm.
    /// </summary>
    BadAlgorithm        = 1,
    /// <summary>
    /// Request is not allowed or supported.
    /// </summary>
    BadRequest          = 3,
    /// <summary>
    /// Request has wrong data format.
    /// </summary>
    BadDataFormat       = 6,
    /// <summary>
    /// The TSA's time source is not available.
    /// </summary>
    TimeNotAvailable    = 15,
    /// <summary>
    /// The requested policy ID is not supported by TSA.
    /// </summary>
    BadPolicy           = 16,
    /// <summary>
    /// The requested X.509 extension is not supported by TSA.
    /// </summary>
    BadExtension        = 17,
    /// <summary>
    /// The additional requested information is not available or cannot be recognized by TSA.
    /// </summary>
    NoMoreInfoAvailable = 18,
    /// <summary>
    /// Internal server error.
    /// </summary>
    ServerError         = 26
}