using System;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains OIDs for most commonly used X.509 certificate and certificate revocation list extensions.
/// </summary>
public static class X509ExtensionOid {
    /// <summary>
    /// Represents Microsoft Cross-Certificate Distribution Points extension object identifier (OID).
    /// See <see cref="X509CrossCertificateDistributionPointsExtension"/> for more details.
    /// </summary>
    public const String CrossCDP                     = "1.3.6.1.4.1.311.10.9.1";
    /// <summary>
    /// Represents V1 Microsoft certificate template extension object identifier (OID).
    /// </summary>
    public const String CertificateTemplateName      = "1.3.6.1.4.1.311.20.2";
    /// <summary>
    /// Represents Microsoft CA Version extension object identifier (OID).
    /// See <see cref="X509CAVersionExtension"/> for more details.
    /// </summary>
    public const String CAVersion                    = "1.3.6.1.4.1.311.21.1";
    /// <summary>
    /// Represents Microsoft Previous CA Certificate Hash extension object identifier (OID).
    /// </summary>
    public const String PreviousCaHash               = "1.3.6.1.4.1.311.21.2";
    /// <summary>
    /// Represents Microsoft Minimum Base CRL Version extension object identifier (OID).
    /// </summary>
    public const String VirtualBaseCRL               = "1.3.6.1.4.1.311.21.3";
    /// <summary>
    /// Represents Microsoft Next CRL Publish extension object identifier (OID).
    /// See <see cref="X509NextCRLPublishExtension"/> for more details.
    /// </summary>
    public const String NextCRLPublish               = "1.3.6.1.4.1.311.21.4";
    /// <summary>
    /// Represents V2+ Microsoft Certificate Template Info extension object identifier (OID).
    /// See <see cref="X509CertificateTemplateExtension"/> for more details.
    /// </summary>
    public const String CertTemplateInfoV2           = "1.3.6.1.4.1.311.21.7";
    /// <summary>
    /// Represents Microsoft Application Policies extension object identifier (OID).
    /// See <see cref="X509ApplicationPoliciesExtension"/> for more details.
    /// </summary>
    public const String ApplicationPolicies          = "1.3.6.1.4.1.311.21.10";
    /// <summary>
    /// Represents Microsoft Application Policy Mappings extension object identifier (OID).
    /// See <see cref="X509ApplicationPolicyMappingsExtension"/> for more details.
    /// </summary>
    public const String ApplicationPolicyMappings    = "1.3.6.1.4.1.311.21.11";
    /// <summary>
    /// Represents Microsoft Application Policy Constraints extension object identifier (OID).
    /// See <see cref="X509ApplicationPolicyConstraintsExtension"/> for more details.
    /// </summary>
    public const String ApplicationPolicyConstraints = "1.3.6.1.4.1.311.21.12";
    /// <summary>
    /// Represents Microsoft Published CRL Location extension object identifier (OID).
    /// See <see cref="X509PublishedCrlLocationsExtension"/> for more details.
    /// </summary>
    public const String PublishedCrlLocations        = "1.3.6.1.4.1.311.21.14";
    /// <summary>
    /// Represents Microsoft NTDS CA Security extension object identifier (OID).
    /// See <see cref="X509NtdsSecurityExtension"/> for more details.
    /// </summary>
    public const String NtdsSecurityExtension        = "1.3.6.1.4.1.311.25.2";
    /// <summary>
    /// Represents Certificate Transparency pre-certificate poison extension object identifier (OID).
    /// See <see cref="X509CTPreCertificatePoisonExtension"/> for more details.
    /// </summary>
    public const String CTPrecertificatePoison       = "1.3.6.1.4.1.11129.2.4.3";
    /// <summary>
    /// Represents Authority Information Access extension object identifier (OID).
    /// See <see cref="X509AuthorityInformationAccessExtension"/> for more details.
    /// </summary>
    public const String AuthorityInformationAccess   = "1.3.6.1.5.5.7.1.1";
    /// <summary>
    /// Represents OCSP Nonce extension object identifier (OID).
    /// See <see cref="X509NonceExtension"/> for more details.
    /// </summary>
    public const String OcspNonce                    = "1.3.6.1.5.5.7.48.1.2";
    /// <summary>
    /// Represents OCSP CRL Reference extension object identifier (OID).
    /// See <see cref="X509CRLReferenceExtension"/> for more details.
    /// </summary>
    public const String OcspCRLReference             = "1.3.6.1.5.5.7.48.1.3";
    /// <summary>
    /// Represents OCSP Revocation No-Check extension object identifier (OID).
    /// </summary>
    public const String OcspRevNoCheck               = "1.3.6.1.5.5.7.48.1.5";
    /// <summary>
    /// Represents OCSP Archive Cut-off extension object identifier (OID).
    /// See <see cref="X509ArchiveCutoffExtension"/> for more details.
    /// </summary>
    public const String ArchiveCutoff                = "1.3.6.1.5.5.7.48.1.6";
    /// <summary>
    /// Represents OCSP Service Locator extension object identifier (OID).
    /// See <see cref="X509ServiceLocatorExtension"/> for more details.
    /// </summary>
    public const String ServiceLocator               = "1.3.6.1.5.5.7.48.1.7";
    /// <summary>
    /// Represents Subject Key Identifier (SKI) extension object identifier (OID).
    /// See <see cref="X509SubjectKeyIdentifierExtension"/> for more details.
    /// </summary>
    public const String SubjectKeyIdentifier         = "2.5.29.14";
    /// <summary>
    /// Represents Key Usage extension object identifier (OID).
    /// See <see cref="X509KeyUsageExtension"/> for more details.
    /// </summary>
    public const String KeyUsage                     = "2.5.29.15";
    /// <summary>
    /// Represents Subject Alternative Names (SAN) extension object identifier (OID).
    /// See <see cref="X509SubjectAlternativeNamesExtension"/> for more details.
    /// </summary>
    public const String SubjectAlternativeNames      = "2.5.29.17";
    /// <summary>
    /// Represents Issuer Alternative Names (IAN) extension object identifier (OID).
    /// See <see cref="X509IssuerAlternativeNamesExtension"/> for more details.
    /// </summary>
    public const String IssuerAlternativeNames       = "2.5.29.18";
    /// <summary>
    /// Represents Basic Constraints extension object identifier (OID).
    /// See <see cref="X509BasicConstraintsExtension"/> for more details.
    /// </summary>
    public const String BasicConstraints             = "2.5.29.19";
    /// <summary>
    /// Represents CRL Number extension object identifier (OID).
    /// See <see cref="X509CRLNumberExtension"/> for more details.
    /// </summary>
    public const String CRLNumber                    = "2.5.29.20";
    /// <summary>
    /// Represents CRL entry revocation reason extension object identifier (OID).
    /// </summary>
    public const String CRLReasonCode                = "2.5.29.21";
    /// <summary>
    /// Represents Delta CRL Indicator extension object identifier (OID).
    /// </summary>
    public const String DeltaCRLIndicator            = "2.5.29.27";
    /// <summary>
    /// Represents Issuing Distribution Points (IDP) extension object identifier (OID).
    /// See <see cref="X509IssuingDistributionPointsExtension"/> for more details.
    /// </summary>
    public const String IssuingDistributionPoint     = "2.5.29.28";
    /// <summary>
    /// Represents Name Constraints extension object identifier (OID).
    /// See <see cref="X509NameConstraintsExtension"/> for more details.
    /// </summary>
    public const String NameConstraints              = "2.5.29.30";
    /// <summary>
    /// Represents CRL Distribution Points extension object identifier (OID).
    /// See <see cref="X509CRLDistributionPointsExtension"/> for more details.
    /// </summary>
    public const String CRLDistributionPoints        = "2.5.29.31";
    /// <summary>
    /// Represents Certificate Policies extension object identifier (OID).
    /// See <see cref="X509CertificatePoliciesExtension"/> for more details.
    /// </summary>
    public const String CertificatePolicies          = "2.5.29.32";
    /// <summary>
    /// Represents Certificate Policy Mappings extension object identifier (OID).
    /// See <see cref="X509CertificatePolicyMappingsExtension"/> for more details.
    /// </summary>
    public const String CertificatePolicyMappings    = "2.5.29.33";
    /// <summary>
    /// Represents Authority Key Identifier (AKI) extension object identifier (OID).
    /// See <see cref="X509AuthorityKeyIdentifierExtension"/> for more details.
    /// </summary>
    public const String AuthorityKeyIdentifier       = "2.5.29.35";
    /// <summary>
    /// Represents Certificate Policy Constraints extension object identifier (OID).
    /// See <see cref="X509CertificatePolicyConstraintsExtension"/> for more details.
    /// </summary>
    public const String CertificatePolicyConstraints = "2.5.29.36";
    /// <summary>
    /// Represents Enhanced Key Usage (EKU) extension object identifier (OID).
    /// See <see cref="X509EnhancedKeyUsageExtension"/> for more details.
    /// </summary>
    public const String EnhancedKeyUsage             = "2.5.29.37";
    /// <summary>
    /// Represents Freshest CRL extension object identifier (OID).
    /// See <see cref="X509FreshestCRLExtension"/> for more details.
    /// </summary>
    public const String FreshestCRL                  = "2.5.29.46";
}