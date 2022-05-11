using System;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// Defines the general-enrollment flags.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum CertificateTemplateFlags {
        /// <summary>
        /// None.
        /// </summary>
        None             = 0,
        /// <summary>
        /// This flag is reserved and not used.
        /// </summary>
        EnrolleeSuppliesSubject = 0x1, // 1
        /// <summary>
        /// This flag is reserved and not used.
        /// </summary>
        AddEmail                = 0x2, // 2
        /// <summary>
        /// This flag is reserved and not used.
        /// </summary>
        AddObjectIdentifier     = 0x4, // 4
        /// <summary>
        /// This flag is reserved and not used.
        /// </summary>
        DsPublish               = 0x8, // 8
        /// <summary>
        /// This flag is reserved and not used.
        /// </summary>
        AllowKeyExport          = 0x10, // 16
        /// <summary>
        /// This flag indicates whether clients can perform autoenrollment for the specified template.
        /// </summary>
        Autoenrollment          = 0x20, // 32
        /// <summary>
        /// This flag indicates that this certificate template is for an end entity that represents a machine.
        /// </summary>
        MachineType             = 0x40, // 64
        /// <summary>
        /// This flag indicates a certificate request for a CA certificate.
        /// </summary>
        IsCA                    = 0x80, // 128
        /// <summary>
        /// Adds requester distinguished name 
        /// </summary>
        AddDistinguishedName    = 0x100, // 256
        /// <summary>
        /// This flag indicates that a certificate based on this section needs to include a template name certificate extension.
        /// </summary>
        AddTemplateName         = 0x200, // 512
        /// <summary>
        /// This flag indicates a certificate request for cross-certifying a certificate.
        /// </summary>
        IsCrossCA               = 0x800, // 2048
        /// <summary>
        /// This flag indicates that the record of a certificate request for a certificate that is issued need not be persisted by the CA.
        /// <para><strong>Windows Server 2003, Windows Server 2008</strong> - this flag is not supported.</para>
        /// </summary>
        DoNotPersistInDB        = 0x1000, // 4096
        /// <summary>
        /// This flag indicates that the template SHOULD not be modified in any way.
        /// </summary>
        IsDefault               = 0x10000, // 65536
        /// <summary>
        /// This flag indicates that the template MAY be modified if required.
        /// </summary>
        IsModified              = 0x20000,  // 131072
        /// <summary>
        /// N/A
        /// </summary>
        IsDeleted               = 0x40000,
        /// <summary>
        /// N/A
        /// </summary>
        PolicyMismatch          = 0x80000
    }
}
