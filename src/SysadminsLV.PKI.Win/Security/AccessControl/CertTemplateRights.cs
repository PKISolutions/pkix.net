using System;

namespace SysadminsLV.PKI.Security.AccessControl {
    /// <summary>
    /// Contains certificate template permission enumeration.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum CertTemplateRights {
        /// <summary>
        /// The caller has all permissions on the object.
        /// </summary>
        FullControl = 0x100,
        /// <summary>
        /// The caller has read-only permissions on the object.
        /// </summary>
        Read        = 0x20,
        /// <summary>
        /// The caller has write permissions on the object. This includes object deletion permissions.
        /// </summary>
        Write       = 0x40,
        /// <summary>
        /// The caller can enroll a certificate.
        /// </summary>
        Enroll      = 0x4000000,
        /// <summary>
        /// The caller can autoenroll a certificate.
        /// </summary>
        Autoenroll  = 0x8000000
    }
}