namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Contains values that represent nonce status. Nonce is often used in Time-Stamp Protocol (TSP), Online Certificate Status Protocol (OCSP).
/// </summary>
public enum NonceStatus {
    /// <summary>
    /// Nonce information is not available.
    /// </summary>
    NotAvailable = 0,
    /// <summary>
    /// Nonce values are presented in request and response and they both match.
    /// </summary>
    NonceMatch,
    /// <summary>
    /// Nonce value is presented in request and is either, not presented in response or nonce values don't match.
    /// </summary>
    NonceMismatch,
}