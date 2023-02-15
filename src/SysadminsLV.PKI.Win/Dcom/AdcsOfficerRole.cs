using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Contains enumeration of ADCS Certification Authority roles
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum AdcsOfficerRole {
        /// <summary>
        /// Caller has no roles on CA server.
        /// </summary>
        None          = 0,
        /// <summary>
        /// Caller has CA administrator rights on CA server.
        /// </summary>
        Administrator = 1,
        /// <summary>
        /// Caller has CA officer rights on CA server.
        /// </summary>
        Officer       = 2,
        /// <summary>
        /// Caller has rights to manage audit settings on CA server.
        /// </summary>
        Auditor       = 4,
        /// <summary>
        /// Caller has operator rights on CA server.
        /// </summary>
        Operator      = 8,
        /// <summary>
        /// Utility value used to mask management and client rights.
        /// </summary>
        MaskRoles     = 0xff,
        /// <summary>
        /// Caller has read permissions on CA server and can read CA configuration details.
        /// </summary>
        Reader        = 0x100,
        /// <summary>
        /// Caller has permissions to enroll certificates on CA server.
        /// </summary>
        Enroller      = 0x200
    }
}