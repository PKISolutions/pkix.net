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
        /// Undefined.
        /// </summary>
        Undefined        = 0x00000001, // 1
        /// <summary>
        /// Reserved. All protocols MUST ignore this flag.
        /// </summary>
        AddEmail         = 0x00000002, // 2, Reserved
        /// <summary>
        /// Undefined.
        /// </summary>
        Undefined2       = 0x00000004, // 4
        /// <summary>
        /// Reserved. All protocols MUST ignore this flag.
        /// </summary>
        DsPublish        = 0x00000008, // 8, Reserved
        /// <summary>
        /// Reserved. All protocols MUST ignore this flag.
        /// </summary>
        AllowKeyExport   = 0x00000010, // 16, Reserved
        /// <summary>
        /// This flag indicates whether clients can perform autoenrollment for the specified template.
        /// </summary>
        Autoenrollment   = 0x00000020, // 32
        /// <summary>
        /// This flag indicates that this certificate template is for an end entity that represents a machine.
        /// </summary>
        MachineType      = 0x00000040, // 64
        /// <summary>
        /// This flag indicates a certificate request for a CA certificate.
        /// </summary>
        IsCA             = 0x00000080, // 128
        /// <summary>
        /// This flag indicates that a certificate based on this section needs to include a template name certificate extension.
        /// </summary>
        AddTemplateName  = 0x00000200, // 512
        /// <summary>
        /// This flag indicates that the record of a certificate request for a certificate that is issued need not be persisted by the CA.
        /// <para><strong>Windows Server 2003, Windows Server 2008</strong> - this flag is not supported.</para>
        /// </summary>
        DoNotPersistInDB = 0x00000400, // 1024
        /// <summary>
        /// This flag indicates a certificate request for cross-certifying a certificate.
        /// </summary>
        IsCrossCA        = 0x00000800, // 2048
        /// <summary>
        /// This flag indicates that the template SHOULD not be modified in any way.
        /// </summary>
        IsDefault        = 0x00010000, // 65536
        /// <summary>
        /// This flag indicates that the template MAY be modified if required.
        /// </summary>
        IsModified       = 0x00020000  // 131072
    }
}
