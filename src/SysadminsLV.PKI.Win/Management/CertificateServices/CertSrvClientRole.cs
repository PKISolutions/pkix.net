using System;

namespace SysadminsLV.PKI.Management.CertificateServices;
/// <summary>
/// Defines possible roles which are used by Certification Authority.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertSrvClientRole {
    /// <summary>
    /// Caller has CA administrator capability.
    /// </summary>
    Administrator = 0x00000001, // 1
    /// <summary>
    /// Caller has CA officer capability.
    /// </summary>
    Officer       = 0x00000002, // 2
    /// <summary>
    /// Caller has CA auditor capability.
    /// </summary>
    Auditor       = 0x00000004, // 4
    /// <summary>
    /// Caller has CA backup capability.
    /// </summary>
    Operator      = 0x00000008, // 8
    /// <summary>
    /// Caller has CA read access.
    /// </summary>
    Read          = 0x00000100, // 256
    /// <summary>
    /// Caller has enrollment access.
    /// </summary>
    Enroll        = 0x00000200, // 512
}
