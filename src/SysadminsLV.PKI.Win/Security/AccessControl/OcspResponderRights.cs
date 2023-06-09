using System;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Defines possible permissions which are used by Certification Authority.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum OcspResponderRights {
        /// <summary>
        /// Identity can update the configuration information at the responder.
        /// </summary>
        Manage  = 0x1,
        /// <summary>
        /// Identity can read the configuration information at the responder.
        /// </summary>
        Read    = 0x100,
        /// <summary>
        /// Identity can request the response status for a particular certificate from the responder.
        /// </summary>
        Request = 0x200
    }
}