using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database;
/// <summary>
/// Contains enumeration of valid certificate request types.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum AdcsDbRequestType {
    /// <summary>
    /// None.
    /// </summary>
    None         = 0,
    /// <summary>
    /// Request is in PKCS#10 format.
    /// </summary>
    PKCS10       = 0x100,
    /// <summary>
    /// Request is in Netscape Keygen format.
    /// </summary>
    Keygen       = 0x200,
    /// <summary>
    /// Request is in PKCS#7 format.
    /// </summary>
    PKCS7        = PKCS10 | Keygen,
    /// <summary>
    /// Request is in CMC format.
    /// </summary>
    CMC          = 0x400,
    /// <summary>
    /// Request is submitted via RPC interface.
    /// </summary>
    RPC          = 0x20000,
    /// <summary>
    /// Full response is generated.
    /// </summary>
    FullResponse = 0x40000,
    /// <summary>
    /// N/A
    /// </summary>
    CRL          = 0x80000,
    /// <summary>
    /// N/A
    /// </summary>
    Machine      = 0x100000,
    /// <summary>
    /// Request is Request On Behalf Of (ROBO).
    /// </summary>
    ROBO         = 0x200000,
    /// <summary>
    /// N/A
    /// </summary>
    NoClientID   = 0x400000,
    /// <summary>
    /// N/A
    /// </summary>
    ConnectOnly  = 0x800000
}
