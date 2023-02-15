using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum CertConfigLocation {
        /// <summary>
        /// Not used.
        /// </summary>
        None            = 0,
        /// <summary>
        /// Certification Authority was found in Active Directory registrations.
        /// </summary>
        DsEntry         = 1,
        /// <summary>
        /// Certification Authority was found in shared folder (deprecated starting with Windows Server 2003).
        /// </summary>
        SharedFolder    = 2,
        /// <summary>
        /// Certification Authority was found in local registry.
        /// </summary>
        Registry        = 4,
        /// <summary>
        /// Certification Authority was found in local registry and is local CA.
        /// </summary>
        Local           = 8,
        /// <summary>
        /// Certification Authority was found in local registry as parent CA of the current CA server.
        /// </summary>
        RegistryParent  = 0x10
    }
}
