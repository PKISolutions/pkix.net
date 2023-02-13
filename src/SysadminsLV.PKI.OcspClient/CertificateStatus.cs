namespace PKI.OCSP;

/// <summary>
///  Defines the status of a certificate requested in the OCSP Request. The status is defined in RFC2560.
/// </summary>
public enum CertificateStatus {
    /// <summary>
    ///  Indicates a positive response to the status inquiry. At a minimum, this positive response indicates that the certificate is not revoked,
    ///  but does not necessarily mean that the certificate was ever issued or that the time at which the response was produced is within the
    ///  certificate's validity interval. Response extensions may be used to convey additional information on assertions made by the responder
    ///  regarding the status of the certificate such as positive statement about issuance, validity, etc.
    /// </summary>
    Good = 0,
    /// <summary>
    ///  Indicates that the certificate has been revoked (either permanently or temporarily (on hold)).
    /// </summary>
    Revoked = 1,
    /// <summary>
    ///  Indicates that the responder doesn't know about the certificate being requested.
    /// </summary>
    Unknown = 2
}