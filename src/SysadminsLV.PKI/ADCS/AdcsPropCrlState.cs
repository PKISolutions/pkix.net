using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains enumeration values for certificate state used by <see cref="ICertPropReaderD"/> interface.
/// </summary>
public enum AdcsPropCrlState {
    /// <summary>
    /// This certificate's CRL is managed by a different certificate.
    /// </summary>
    Error         = 1,
    /// <summary>
    /// This indexed signing certificate is time-valid, but has been revoked by its issuer.
    /// Certificate's associated key MUST NOT be used to sign CRLs.
    /// </summary>
    Revoked       = 2,
    /// <summary>
    /// This indexed signing certificate is still used to sign CRLs.
    /// </summary>
    Valid         = 3,
    /// <summary>
    /// The indexed signing certificate is expired and is not be used to sign CRLs.
    /// </summary>
    Invalid       = 4,
    /// <summary>
    /// The property is unavailable.
    /// </summary>
    NotApplicable = unchecked((Int32)0xffffffff)
}