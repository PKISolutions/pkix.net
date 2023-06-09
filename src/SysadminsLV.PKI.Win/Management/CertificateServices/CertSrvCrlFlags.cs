using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Defines certificate revocation list (and chaining engine) flags.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    /// <remarks>Not all CA versions support full list.</remarks>
    [Flags]
    public enum CertSrvCrlFlags {
        /// <summary>
        /// No flags are defined.
        /// </summary>
        None                            = 0x00000000,  // 0
        /// <summary>
        /// The CA server will use oldest unexpired Base CRL for certificate revocation checking. Otherwise, the most recent Base CRL is used.
        /// </summary>
        DeltaUseOldestUnexpiredBase     = 0x00000001,    // 1
        /// <summary>
        /// Deletes CRLs signed by the expired CA keys.
        /// </summary>
        DeleteExpiredCRLs               = 0x00000002,    // 2
        /// <summary>
        /// The CA server will mark CRL Number extension as critical. If a target application doesn't recognize this extension, a CRL will be rejected.
        /// </summary>
        CRLNumberCritical               = 0x00000004,    // 4
        /// <summary>
        /// The CA server will ignore certificate revocation checking failures.
        /// <p><strong>Note</strong>: You should not enable this flag in production environments.</p>
        /// </summary>
        RevCheckIgnoreOffline           = 0x00000008,    // 8
        /// <summary>
        /// The CA server will ignore invalid Certificate Policies extension in requests.
        /// </summary>
        IgnoreInvalidPolicies           = 0x00000010,    // 16
        /// <summary>
        /// When a CA server is configured to use the unmodified subject that is supplied in the certificate request, the policy module should not make any
        /// changes to the subject that is in the certificate request.
        /// </summary>
        RebuildModifiedSubjectOnly      = 0x00000020,    // 32
        /// <summary>
        /// N/A
        /// </summary>
        SaveFailedCerts                 = 0x00000040,    // 64
        /// <summary>
        /// The CA server ignores unknown CMC attributes in the request.
        /// </summary>
        IgnoreUnknownCMCAttributes      = 0x00000080,    // 128
        /// <summary>
        /// The CA server ignores trust errors for cross-certificates during certificate chain building.
        /// </summary>
        IgnoreCrossCertTrustError       = 0x00000100,    // 256
        /// <summary>
        /// The CA will publish expired revoked certificates in CRLs.
        /// </summary>
        PublishExpiredCertCRLs          = 0x00000200,    // 512
        /// <summary>
        /// The CA enforces enrollment agent restrictions.
        /// </summary>
        EnforceEnrollmentAgent          = 0x00000400,    // 1024
        /// <summary>
        /// The CA server will not re-order relative distinguished name (RDN) in the certificate request.
        /// </summary>
        DisableRDNReorder               = 0x00000800,    // 2048
        /// <summary>
        /// Instructs Root CA server to not generate root cross-certificates after Root CA renewal with new key pair.
        /// <p><strong>Note:</strong> this flag has no effect on any type of Subordinate CA.</p>
        /// </summary>
        DisableRootCrossCerts           = 0x00001000,    // 4096
        /// <summary>
        ///  The CA will dump request response to console.
        /// </summary>
        LogFullResponse                 = 0x00002000,    // 8192
        /// <summary>
        /// Instructs CA server to use CA Exchange template instead of using automatically generated short-lived certificates for key archival.
        /// </summary>
        UseXCHGCertTemplate             = 0x00004000,    // 16384
        /// <summary>
        /// Instructs Root CA server to use Cross Certification Authority template during Root CA renewal with new key pair, instead of using
        /// automatically generated cross-certificates.
        /// <p><strong>Note:</strong> this flag has no effect on any type of Subordinate CA.</p>
        /// </summary>
        UseCrossCertTemplate            = 0x00008000,    // 32768
        /// <summary>
        /// The CA server will accept certificate subject submitted as a part of request attributes.
        /// </summary>
        AllowRequestAttributeSubject    = 0x00010000,    // 65536
        /// <summary>
        /// The CA server ignores empty CRL Distribution Points (CDP) extension for non-root certificates.
        /// </summary>
        RevCheckIgnoreNoRevCheck        = 0x00020000,    // 131072
        /// <summary>
        /// The CA server will preserve CA certificate in database and certificate store even if the certificate is not timely valid.
        /// </summary>
        PreserveExpiredCerts            = 0x00040000,    // 262144
        /// <summary>
        ///  The CA server will preserve CA certificates in database and certificate store even if the certificates are revoked.
        /// </summary>
        PreserveRevokedCACerts          = 0x00080000,    // 524288
        /// <summary>
        /// The CA server will preserve revoked CA certificates in database and certificate store.
        /// <para><strong>Windows Server 2003, Windows Server 2008</strong>: this flag is not supported.</para>
        /// </summary>
        DisableChainVerification        = 0x00100000,    // 1048576
        /// <summary>
        /// N/A
        /// <para><strong>Windows Server 2003, Windows Server 2008</strong>: this flag is not supported.</para>
        /// </summary>
        BuildRootCaCrlEntriesBasedOnKey = 0x00200000    // 2097152
    }
}
