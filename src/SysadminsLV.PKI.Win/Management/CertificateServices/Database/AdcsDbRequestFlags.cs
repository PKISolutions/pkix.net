using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database;
/// <summary>
/// Represents request flags.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum AdcsDbRequestFlags {
    /// <summary>
    /// None.
    /// </summary>
    None                  = 0,
    /// <summary>
    /// Force ASN.1 TeletexString type to encode subject attributes.
    /// </summary>
    ForceTeletex          = 0x001,
    /// <summary>
    /// Request is renewal request.
    /// </summary>
    Renewal               = 0x002,
    /// <summary>
    /// Force ASN.1 UTF8String type to encode subject attributes.
    /// </summary>
    ForceUTF8             = 0x004,
    /// <summary>
    /// Request is CA Exchange certificate.
    /// </summary>
    XchgCert              = 0x008,
    /// <summary>
    /// Request submitted via Request On Behalf Of (ROBO).
    /// </summary>
    ROBO                  = 0x010,
    /// <summary>
    /// Subject is copied from request to issued certificate unmodified.
    /// </summary>
    SubjectUnmodified     = 0x020,
    /// <summary>
    /// Archived key hash matches the hash of archived key.
    /// </summary>
    ValidEncryptedKeyHash = 0x040,
    /// <summary>
    /// Request is cross-certificate request.
    /// </summary>
    CrossCert             = 0x080,
    /// <summary>
    /// Force ASN.1 UTF8String type to encode subject attributes.
    /// </summary>
    EnforceUTF8           = 0x100,
    /// <summary>
    /// Request contains explicit CA certificate and private key CA must use to sign request.
    /// </summary>
    DefinedCaCert         = 0x200,
    /// <summary>
    /// CA failed to publish request.
    /// </summary>
    PublishError          = unchecked((Int32)0x80000000)
}
