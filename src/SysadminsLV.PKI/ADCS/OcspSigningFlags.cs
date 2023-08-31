using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains values to configure OCSP signing certificate management behavior.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum OcspSigningFlags {
    /// <summary>
    /// None.
    /// </summary>
    None                      = 0,
    /// <summary>
    /// Acquire a private key silently.
    /// </summary>
    Silent                    = 1,
    /// <summary>
    /// Use a CA certificate in this configuration for signing an OCSP response. This option is available only if the responder
    /// service is installed on the CA computer.
    /// </summary>
    UseCaCert                 = 2,
    /// <summary>
    /// Enable a responder service to automatically transition to a renewed signing certificate.
    /// </summary>
    SigningCertAutoRenewal    = 4,
    /// <summary>
    /// Force a delegated signing certificate to be signed by the CA.
    /// </summary>
    ForceDelegatedCert        = 8,
    /// <summary>
    /// Automatically discover a delegated signing certificate.
    /// </summary>
    AutoDiscoverSigningCert   = 0x10,
    /// <summary>
    /// Manually assign a signing certificate.
    /// </summary>
    ManualSigningCert         = 0x20,
    /// <summary>
    /// A responder ID includes a hash of the public key of the signing certificate (default).
    /// </summary>
    ResponderIdKeyHash        = 0x40,
    /// <summary>
    /// A responder ID includes the name of the subject in a signing certificate.
    /// </summary>
    ResponderIdCertName       = 0x80,
    /// <summary>
    /// Enable NONCE extension to be processed by a responder service.
    /// </summary>
    AllowNonce                = 0x100,
    /// <summary>
    /// A responder service can enroll for a signing certificate.
    /// </summary>
    SigningCertAutoEnrollment = 0x200
}