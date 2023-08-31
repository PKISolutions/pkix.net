using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Contains enumeration values for 'pKIEnrollmentService' entry in Active Directory.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum DsEnrollServerFlag {
    /// <summary>
    /// None.
    /// </summary>
    None                         = 0,
    /// <summary>
    /// Enrollment Server (CA) does not support certificate templates.
    /// </summary>
    NoTemplateSupport            = 1,
    /// <summary>
    /// Enrollment Server (CA) supports NTLM authentication.
    /// </summary>
    SupportsNTAuthentication     = 2,
    /// <summary>
    /// Enrollment Server (CA) supports manual authentication.
    /// </summary>
    SupportsManualAuthentication = 4,
    /// <summary>
    /// The operating system that hosts the Enrollment Server (CA) is an advanced server.
    /// </summary>
    AdvancedServer               = 8
}