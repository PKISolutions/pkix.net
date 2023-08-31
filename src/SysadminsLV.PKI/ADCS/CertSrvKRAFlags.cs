using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Defines Key Recovery Agent (KRA) flags.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertSrvKRAFlags {
    /// <summary>
    /// No flags are defined.
    /// </summary>
    None                      = 0x00000000,  // 0
    /// <summary>
    /// Enables key archival for certificates issued by other (or 3rd party) CA.
    /// </summary>
    EnableForeign             = 0x00000001, // 1
    /// <summary>
    /// Enforces key archival even if the submitted public and private key pair cannot be verified.
    /// </summary>
    SaveBadRequestKey         = 0x00000002, // 2
    /// <summary>
    /// Enforces key archival for all incoming certificate requests. Do not use this flag unless all certificate
    /// requests support key archival.
    /// </summary>
    EnableArchiveAll          = 0x00000004,  // 4
    /// <summary>
    /// Disables default cryptographic service provider (CSP) usage for public and private key pair verification.
    /// <para><strong>Windows Server 2003</strong>: this flag is not supported.</para>
    /// </summary>
    DisableUseDefaultProvider = 0x00000008  // 8
}