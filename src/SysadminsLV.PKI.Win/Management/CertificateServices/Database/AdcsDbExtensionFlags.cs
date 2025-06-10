using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database;
/// <summary>
/// Contains enumeration values that represent extension row flags in CA database.
/// This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.
/// </summary>
[Flags]
public enum AdcsDbExtensionFlags {
    /// <summary>
    /// None.
    /// </summary>
    None               = 0,
    /// <summary>
    /// Extension is marked as critical.
    /// </summary>
    Critical           = 0x1,
    /// <summary>
    /// Extension is disabled.
    /// </summary>
    Disabled           = 0x2,
    /// <summary>
    /// Extension originated from request.
    /// </summary>
    OriginRequest      = 0x00010000,
    /// <summary>
    /// Extension originated from policy module.
    /// </summary>
    OriginPolicy       = 0x00020000,
    /// <summary>
    /// Extension originated from server configuration.
    /// </summary>
    OriginServer       = 0x00040000,
    /// <summary>
    /// Extension originated from CMC attributes.
    /// </summary>
    OriginCmc          = 0x00080000,
    /// <summary>
    /// Extension is set by an administrator.
    /// </summary>
    OriginAdmin        = OriginRequest | OriginPolicy,
    /// <summary>
    /// Extension originated from imported certificate.
    /// </summary>
    OriginImportedCert = OriginPolicy | OriginServer,
    /// <summary>
    /// Extension originated from PKCS#7 attributes.
    /// </summary>
    OriginPkcs7        = OriginAdmin | OriginImportedCert,
    /// <summary>
    /// Extension originated from CA certificate.
    /// </summary>
    OriginCaCert       = OriginCmc | OriginRequest
}
