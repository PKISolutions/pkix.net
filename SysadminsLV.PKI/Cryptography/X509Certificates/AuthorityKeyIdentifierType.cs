using System;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains enumeration of components included in the Authority Key Identifier (AKI) certificate extension.
/// <para>This enumeration has a <see cref="System.FlagsAttribute"/> attribute that allows a bitwise combination of
/// its member values.</para>
/// </summary>
[Flags]
public enum AuthorityKeyIdentifierType {
    /// <summary>
    /// No components are included in the AKI extension. The value is invalid.
    /// </summary>
    None                = 0,
    /// <summary>
    /// AKI extension has <strong>KeyIdentifier</strong> component.
    /// </summary>
    KeyIdentifier       = 1,
    /// <summary>
    /// AKI extension contains issuer alternative names component.
    /// </summary>
    AlternativeNames    = 2,
    /// <summary>
    /// AKI extension contains issuer certificate's serial number.
    /// </summary>
    SerialNumber        = 4
}