using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Defines client roles on Online Responder.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum OcspResponderClientRole {
    /// <summary>
    /// The caller has no roles.
    /// </summary>
    None          = 0x00000000, // 0
    /// <summary>
    /// The caller can update the configuration information at the responder. 
    /// </summary>
    Administrator = 0x00000001, // 1
    /// <summary>
    /// The caller can read the configuration information at the responder.
    /// </summary>
    Read          = 0x00000100, // 256
    /// <summary>
    /// The caller can request the response status for a particular certificate from the responder.
    /// </summary>
    Request       = 0x00000200 // 512
}