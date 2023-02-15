namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Contains possible ADCS Certification Authority property names
    /// </summary>
    enum AdcsCAPropertyName {
        /// <summary>
        /// Certification Authority file version.
        /// </summary>
        FileVersion              = 0x00000001, // string, 0
        /// <summary>
        /// Certification Authority product version.
        /// </summary>
        ProductVersion           = 0x00000002, // string, 0
        /// <summary>
        /// Exit module Count.
        /// </summary>
        ExitCount                = 0x00000003, // long, 0
        /// <summary>
        /// Exit module description.
        /// </summary>
        ExitDescription          = 0x00000004, // string, 0..ExitCount-1
        /// <summary>
        /// Policy module description.
        /// </summary>
        PolicyDescription        = 0x00000005, // string, 0
        /// <summary>
        /// Certification Authority name.
        /// </summary>
        CaName                   = 0x00000006, // string, 0
        /// <summary>
        /// Sanitized common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </summary>
        SanitizedCaName          = 0x00000007, // string, 0
        /// <summary>
        /// Configuration shared folder path.
        /// </summary>
        SharedFolder             = 0x00000008, // string, 0
        /// <summary>
        /// Parent Certification Authority Name.
        /// </summary>
        ParentCa                 = 0x00000009, // string, 0
        /// <summary>
        /// Certification Authority Type.
        /// </summary>
        CaType                   = 0x0000000A, // long, 0
        /// <summary>
        /// Certification Authority Signature Certificate Count
        /// </summary>
        CaSigCertCount           = 0x0000000B, // long, 0
        /// <summary>
        /// Certification Authority Signature Certificate.
        /// </summary>
        CaSigCert                = 0x0000000C, // binary, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Certification Authority signing certificate Chain.
        /// </summary>
        CaSigCertChain           = 0x0000000D, // binary, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// CA Exchange Certificate Count.
        /// </summary>
        CaXchgCertCount          = 0x0000000E, // long, 0
        /// <summary>
        /// Certification Authority Exchange Certificate.
        /// </summary>
        CaXchgCert               = 0x0000000F, // binary, 0
        /// <summary>
        /// Certification Authority Exchange Certificate Chain.
        /// </summary>
        CaXchgCertChain          = 0x00000010, // binary, 0
        /// <summary>
        /// Base CRL.
        /// </summary>
        BaseCrl                  = 0x00000011, // binary, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Delta CRL.
        /// </summary>
        DeltaCrl                 = 0x00000012, // binary, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Certification Authority Signing Certificates State.
        /// </summary>
        CaCertState              = 0x00000013, // long, 0..CaSigCertCount-1
        /// <summary>
        /// Certification Authority CRL State.
        /// </summary>
        CrlState                 = 0x00000014, // long, 0..CaSigCertCount-1
        /// <summary>
        /// Maximum Property ID.
        /// </summary>
        CaPropIdMax              = 0x00000015, // long, 0
        /// <summary>
        /// Certification Authority Fully Qualified DNS.
        /// </summary>
        DnsName                  = 0x00000016, // string, 0
        /// <summary>
        /// Role Separated Enabled.
        /// </summary>
        RoleSeparationEnabled    = 0x00000017, // long, 0
        /// <summary>
        /// Count Of Required KRAs For Archival.
        /// </summary>
        KraCertUsedCount         = 0x00000018, // long, 0
        /// <summary>
        /// Count Of Registered KRAs.
        /// </summary>
        KraCertCount             = 0x00000019, // long, 0
        /// <summary>
        /// KRA Certificate.
        /// </summary>
        KraCert                  = 0x0000001A, // binary, 0..KraCertCount-1
        /// <summary>
        /// KRA Certificates State.
        /// </summary>
        KraCertState             = 0x0000001B, // long, 0..KraCertCount-1
        /// <summary>
        ///  Advanced Server.
        /// </summary>
        AdvancedServer           = 0x0000001C, // long, 0
        /// <summary>
        /// Configured Certificate Templates.
        /// </summary>
        Templates                = 0x0000001D, // string, 0
        /// <summary>
        /// Base CRL Publishing Status.
        /// </summary>
        BaseCrlPublishStatus     = 0x0000001E, // long, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Delta CRL Publishing State.
        /// </summary>
        DeltaCrlPublishStatus    = 0x0000001F, // long, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Certification Authority Signing Certificate Chain and CRL.
        /// </summary>
        CaSigCertCrlChain        = 0x00000020, // binary, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Certification Authority Exchange Certificate Chain and CRL.
        /// </summary>
        CaXchgCertCrlChain       = 0x00000021, // binary, 0
        /// <summary>
        /// Certification Authority Signing Certificate Status.
        /// </summary>
        CaCertStatusCode         = 0x00000022, // long, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Certification Authority Forward Cross Certificate.
        /// </summary>
        CaForwardCrossCert       = 0x00000023, // binary, 0..CaSigCertCount-2
        /// <summary>
        /// Certification Authority Backward Cross Certificate.
        /// </summary>
        CaBackwardCrossCert      = 0x00000024, // binary, 1..CaSigCertCount-1
        /// <summary>
        /// Certification Authority Forward Cross Certificate State.
        /// </summary>
        CaForwardCrossCertState  = 0x00000025, // long, 0..CaSigCertCount-2
        /// <summary>
        /// A Backward Cross Certificate State.
        /// </summary>
        CaBackwardCrossCertState = 0x00000026, // long, 1..CaSigCertCount-1
        /// <summary>
        /// Certification Authority Signing Certificates Revisions.
        /// </summary>
        CaCertVersion            = 0x00000027, // long, 0..CaSigCertCount-1
        /// <summary>
        /// Sanitized and shortened common name of the Certification Authority in a form as specified in
        /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
        /// </summary>
        SanitizedCaShortName     = 0x00000028, // string, 0
        /// <summary>
        /// CRL Distribution Points.
        /// </summary>
        CertCdpUrls              = 0x00000029, // string, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// Authority Information Access URLs.
        /// </summary>
        CertAiaUrls              = 0x0000002A, // string, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// OCSP URLs.
        /// </summary>
        CertAiaOcspUrls          = 0x0000002B, // string, 0..CaSigCertCount-1. 0xFFFFFFFF = max index
        /// <summary>
        /// CA Locale Name.
        /// </summary>
        LocaleName               = 0x0000002C, // string, 0
        /// <summary>
        /// Subject Template.
        /// </summary>
        SubjectTemplateOIDs      = 0x0000002D // string, 0
    }
}