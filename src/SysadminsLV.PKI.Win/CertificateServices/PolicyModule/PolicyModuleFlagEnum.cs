using System;

namespace PKI.CertificateServices.PolicyModule {
    /// <summary>
    /// Defines default policy module flags.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    /// <remarks>Not all CA versions support full list.</remarks>
    [Flags]
    public enum PolicyModuleFlagEnum {
        /// <summary>
        /// </summary>
        None                            = 0x00000000,    // 0
        /// <summary>
        /// Enables 'Enabled Request Extensions' list processing.
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableRequestExtensions            = 0x00000001,    // 1
        /// <summary>
        /// N/A
        /// <para>This flag is enabled by default on both Standalone and Enterprise CAs.</para>
        /// </summary>
        RequestExtensionList            = 0x00000002,    // 2
        /// <summary>
        /// Enables 'Disabled Request Extensions' list processing. If the flag is enabled and certificate request
        /// contains one or more extemsions from this list, extensions will be discarded.
        /// <para>This flag is enabled by default on both Standalone and Enterprise CAs.</para>
        /// </summary>
        DisableExtensionList            = 0x00000004,    // 4
        /// <summary>
        /// N/A
        /// <para>This flag is enabled by default on both Standalone and Enterprise CAs.</para>
        /// </summary>
        AddOldKeyUsage                    = 0x00000008,    // 8
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        AddOldCertType                    = 0x00000010,    // 16
        /// <summary>
        /// Allows to specify certificate's validity end date. While certificate's validity on Enterprise CAs is (mainly) determined
        /// by certificate template settings, Standalone CAs determines this value by ValidityPeriod and ValidityPeriodUnits
        /// settings only. This flag allows to override ValidityPeriod and ValidityPeriodUnits settings to set certificate's validity.
        /// <para>Note: EndDate value cannot exceed ValidityPeriod and ValidityPeriodUnits settings.</para>
        /// <para>This flag is enabled by default on Standalone CAs.</para>
        /// </summary>
        AttributeEndDate                = 0x00000020,    // 32
        /// <summary>
        /// Marks <strong>Basic Constraints</strong> extension as critical.
        /// <para>This flag is enabled by default on both Standalone and Enterprise CAs.</para>
        /// </summary>
        BasicConstraintsCritical        = 0x00000040,    // 64
        /// <summary>
        /// Enables <strong>Basic Constraints</strong> extension for CA certificates.
        /// <para>This flag is enabled by default on Standalone CAs.</para>
        /// </summary>
        BasicConstraintsCA                = 0x00000080,    // 128
        /// <summary>
        /// Enables <strong>KeyID</strong> (issuer's public key hash) value to appear in <strong>Authority Key Identifier</strong>
        /// (<strong>AKI</strong>) extension.
        /// <para>This flag is enabled by default on both Standalone and Enterprise CAs.</para>
        /// </summary>
        EnableAKIKeyID                    = 0x00000100,    // 256
        /// <summary>
        /// N/A
        /// <para>This flag is enabled on Standalone CAs.</para>
        /// </summary>
        AttributeCA                        = 0x00000200,    // 512
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        IgnoreRequestGroup                = 0x00000400,    // 1024
        /// <summary>
        /// Enables issuer name value to appear in <strong>Authority Key Identifier</strong>
        /// (<strong>AKI</strong>) extension.
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableAKIIssuerName                = 0x00000800,    // 2048
        /// <summary>
        /// Enables issuer certificate's serial number to appear in <strong>Authority Key Identifier</strong>
        /// (<strong>AKI</strong>) extension.
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableAKIIssuerSerial            = 0x00001000,    // 4096
        /// <summary>
        /// Marks <strong>Authority Key Identifier</strong> (<strong>AKI</strong>) extension as critical.
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableAKICritical                = 0x00002000,    // 8192
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        ServerUpgraded                    = 0x00004000,    // 16384
        /// <summary>
        /// Enables <strong>Enhanced Key Usages</strong> (<strong>EKU</strong>) extensions passing as unauthenticated
        /// request attribute (rather than including EKU extension as authenticated extension in the request).
        /// <para>This flag is enabled by default on Standalone CAs.</para>
        /// </summary>
        AttributeEKU                    = 0x00008000,    // 32768
        /// <summary>
        /// N/A
        /// <para>This flag is enabled by default on Enterprise CAs.</para>
        /// </summary>
        EnableDefaultSMIME                = 0x00010000,    // 65536
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EmailOptional                    = 0x00020000,    // 131072
        /// <summary>
        /// Enables <strong>Subject Alternative Name</strong> (<strong>SAN</strong>) extensions passing as unauthenticated
        /// request attribute (rather than including SAN extension as authenticated extension in the request).
        /// <para>Note: Do not enable this flag on Enterprise CAs. Instead, inclue SAN extension directly in the request.</para>
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        AttributeSubjectAlternativeName    = 0x00040000,    // 262144
        /// <summary>
        /// Allows <strong>Certification Authority</strong> (<strong>CA</strong>) to chase a referral for user or computer
        /// information in a trusted forest. When referrals are not chased and the user information is not available, the
        /// request will be denied if the user is enrolling from another forest. Referral chasing is not enabled by default
        /// as unintended template enumeration and enrollment may occur in some scenarios.
        /// <para>This flag is necessary only for Cross-Forest Enrollment scenarios.</para>
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableLDAPReferrals                = 0x00080000,    // 524288
        /// <summary>
        /// N/A
        /// <para>This flag is enabled by default on Enterprise CAs.</para>
        /// </summary>
        EnableChaseClientDC                = 0x00100000,    // 1048576
        /// <summary>
        /// Enables template list load from Active Directory audit.
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        AuditCertTemplateLoad            = 0x00200000,    // 2097152
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        DisableOldOSCNUPN                = 0x00400000,    // 4194304
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        DisableLDAPPackageList            = 0x00800000,    // 8388608
        /// <summary>
        /// N/A
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableUPNMap                    = 0x01000000,    // 16777216
        /// <summary>
        /// Enables <strong>id-pkix-ocsp-nocheck</strong> extension in the request.
        /// <para><strong>Windows Server 2003</strong>: this flag is not supported.</para>
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableOCSPRevNoCheck            = 0x02000000,    // 33554432
        /// <summary>
        /// Enables certificate renewel on behalf of other user or computer.
        /// <para><strong>Windows Server 2003, Windows Server 2008</strong>: this flag is not supported.</para>
        /// <para>This flag is not enabled by default.</para>
        /// </summary>
        EnableRenewOnBehalfOf            = 0x04000000    // 67108864
    }
}
