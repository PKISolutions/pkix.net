using System;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a combination of possible Time-Stamp Response validation failures.
/// </summary>
[Flags]
public enum TspValidationErrorStatus {
    /// <summary>
    /// TSP response successfully passed all validations.
    /// </summary>
    None                      = 0x0,
    /// <summary>
    /// TSP response does not include message body. This indicates that request was rejected by a TSA.
    /// </summary>
    NoResponse                = 0x1,
    /// <summary>
    /// TSP response does not include required certificates to validate TSP response signature.
    /// </summary>
    MissingSigningCertificate = 0x2,
    /// <summary>
    /// TSP request included a Nonce, but Nonce message was not included in response.
    /// </summary>
    MissingNonce              = 0x4,
    /// <summary>
    /// Nonce values in request and in response doesn't match.
    /// </summary>
    NonceMismatch             = 0x8,
    /// <summary>
    /// TSP response failed signature validation. This indicates that response message was tampered.
    /// </summary>
    SignatureMismatch         = 0x10,
    /// <summary>
    /// TSP response's signer certificate is not valid for timestamp usage.
    /// </summary>
    SignerNotValidForUsage    = 0x20,
    /// <summary>
    /// Data to be signed included in request does not match the signed data in response.
    /// </summary>
    MessageImprintMismatch    = 0x40
}