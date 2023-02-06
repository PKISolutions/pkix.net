using System;

namespace SysadminsLV.PKI.Cryptography.X509Certificates; 

/// <summary>
/// An X509KeySpecFlags enumeration value that specifies the supported key operations.
/// <para>This enumeration has a <see cref="System.FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum X509KeySpecFlags {
    /// <summary>
    /// The intended use is not identified. This value is set if the provider that supports the key is a
    /// Cryptography API: Next Generation (CNG) key storage provider (KSP).
    /// </summary>
    AT_NONE			= 0,
    /// <summary>
    /// Keys used to encrypt/decrypt session keys.
    /// </summary>
    AT_KEYEXCHANGE	= 1,
    /// <summary>
    /// Keys used to create and verify digital signatures.
    /// </summary>
    AT_SIGNATURE	= 2
}