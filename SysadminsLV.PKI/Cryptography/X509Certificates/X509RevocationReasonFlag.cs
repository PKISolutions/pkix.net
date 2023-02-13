using System;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents certificate revocation flags. This enumeration is used by <see cref="X509DistributionPoint"/> and
/// <see cref="X509IssuingDistributionPointsExtension"/> types.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum X509RevocationReasonFlag {
    /// <summary>
    /// No revocation reasons defined.
    /// </summary>
    None                = 0,
    /// <inheritdoc cref="X509RevocationReasons.PrivilegeWithdrawn"/>
    PrivilegeWithdrawn  = 0x1,
    /// <inheritdoc cref="X509RevocationReasons.CertificateHold"/>
    CertificateHold     = 0x2,
    /// <inheritdoc cref="X509RevocationReasons.CeaseOfOperation"/>
    CeaseOfOperation    = 0x4,
    /// <inheritdoc cref="X509RevocationReasons.Superseded"/>
    Superseded          = 0x8,
    /// <inheritdoc cref="X509RevocationReasons.ChangeOfAffiliation"/>
    ChangeOfAffiliation = 0x10,
    /// <inheritdoc cref="X509RevocationReasons.CACompromise"/>
    CACompromise        = 0x20,
    /// <inheritdoc cref="X509RevocationReasons.KeyCompromise"/>
    KeyCompromise       = 0x40,
    /// <inheritdoc cref="X509RevocationReasons.Unspecified"/>
    Unspecified         = 0x80,
    /// <inheritdoc cref="X509RevocationReasons.AACompromise"/>
    AACompromise        = 0x8000
}