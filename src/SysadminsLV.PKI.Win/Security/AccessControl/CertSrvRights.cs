using System;

namespace SysadminsLV.PKI.Security.AccessControl;
/// <summary>
/// Defines possible permissions which are used by Certification Authority.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertSrvRights {
    /// <summary>
    /// Identity can manage CA.
    /// </summary>
    ManageCA           = 0x00000001, // 1
    /// <summary>
    /// Identity can issue and manage certificates.
    /// </summary>
    ManageCertificates = 0x00000002, // 2
    /// <summary>
    /// Identity can read CA configuration.
    /// </summary>
    Read               = 0x00000100, // 256
    /// <summary>
    /// Identity can enroll for certificates from CA server.
    /// </summary>
    Enroll             = 0x00000200, // 512
}
