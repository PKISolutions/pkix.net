using System;

namespace SysadminsLV.PKI.OcspClient;

/// <summary>
/// Contains OCSP response compliance warning and error statuses.
/// </summary>
[Flags]
public enum OCSPResponseComplianceError {
    /// <summary>
    /// No compliance errors were found in the OCSP response.
    /// </summary>
    None					= 0,
    /// <summary>
    /// OCSP response do not contains explicit (delegated) certificate in the response and CA certificate is not installed
    /// in the local certificate stores.
    /// </summary>
    MissingCert				= 0x1,
    /// <summary>
    /// Delegated signing certificate is missing id-pkix-ocsp-nocheck extension.
    /// </summary>
    MissingOCSPRevNoCheck	= 0x2,
    /// <summary>
    /// Delegated signing certificate is missing id-kp-OCSPSigning Enhanced Key Usage.
    /// </summary>
    MissingOCSPSigningEKU	= 0x4,
    /// <summary>
    /// Responder ID (either by name or by key) do not match to the signing certificate's Subject field or KeyID.
    /// </summary>
    ResponderIdMismatch		= 0x8,
    /// <summary>
    /// Returned HTTP header do not contains 'application/ocsp-response' entry in Content-header.
    /// </summary>
    InvalidHTTPHeader		= 0x10,
    /// <summary>
    /// Response signing time is set to future.
    /// </summary>
    ResponseNotTimeValid	= 0x20,
    /// <summary>
    /// Response is expired.
    /// </summary>
    UpdateNotTimeValid		= 0x40,
    /// <summary>
    /// Indicates that Nonce extension value in the response do not match the value submitted in the original request.
    /// </summary>
    NonceMismatch			= 0x80,
    /// <summary>
    /// Indicates that information about responded certificate do not match the certificate in the request.
    /// </summary>
    CertIdMismatch			= 0x100,
}