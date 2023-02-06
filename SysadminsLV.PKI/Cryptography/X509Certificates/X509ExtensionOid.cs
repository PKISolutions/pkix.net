using System;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains OIDs for most commonly used X.509 certificate and certificate revocation list
/// extensions.
/// </summary>
/// <remarks>Do not rely on this class until further notice. It is going to change at some point.</remarks>
public static class X509ExtensionOid {
    public const String CertificateExtensions        = "1.2.840.113549.1.9.14";
    public const String CrossCDP                     = "1.3.6.1.4.1.311.10.9.1";
    public const String CertificateTemplate          = "1.3.6.1.4.1.311.20.2";
    public const String CAVersion                    = "1.3.6.1.4.1.311.21.1";
    public const String PreviousCaHash               = "1.3.6.1.4.1.311.21.2";
    public const String VirtualBaseCRL               = "1.3.6.1.4.1.311.21.3";
    public const String NextCRLPublish               = "1.3.6.1.4.1.311.21.4";
    public const String CertTemplateInfoV2           = "1.3.6.1.4.1.311.21.7";
    public const String ApplicationPolicies          = "1.3.6.1.4.1.311.21.10";
    public const String ApplicationPolicyMappings    = "1.3.6.1.4.1.311.21.11";
    public const String ApplicationPolicyConstraints = "1.3.6.1.4.1.311.21.12";
    public const String PublishedCrlLocations        = "1.3.6.1.4.1.311.21.14";
    public const String NtdsSecurityExtension        = "1.3.6.1.4.1.311.25.2";
    public const String AuthorityInformationAccess   = "1.3.6.1.5.5.7.1.1";
    public const String OcspNonce                    = "1.3.6.1.5.5.7.48.1.2";
    public const String OcspCRLReference             = "1.3.6.1.5.5.7.48.1.3";
    public const String OcspRevNoCheck               = "1.3.6.1.5.5.7.48.1.5";
    public const String ArchiveCutoff                = "1.3.6.1.5.5.7.48.1.6";
    public const String ServiceLocator               = "1.3.6.1.5.5.7.48.1.7";
    public const String SubjectKeyIdentifier         = "2.5.29.14";
    public const String KeyUsage                     = "2.5.29.15";
    public const String SubjectAlternativeNames      = "2.5.29.17";
    public const String IssuerAlternativeNames       = "2.5.29.18";
    public const String BasicConstraints             = "2.5.29.19";
    public const String CRLNumber                    = "2.5.29.20";
    public const String CRLReasonCode                = "2.5.29.21";
    public const String DeltaCRLIndicator            = "2.5.29.27";
    public const String IssuingDistributionPoint     = "2.5.29.28";
    public const String NameConstraints              = "2.5.29.30";
    public const String CRLDistributionPoints        = "2.5.29.31";
    public const String CertificatePolicies          = "2.5.29.32";
    public const String CertificatePolicyMappings    = "2.5.29.33";
    public const String AuthorityKeyIdentifier       = "2.5.29.35";
    public const String CertificatePolicyConstraints = "2.5.29.36";
    public const String EnhancedKeyUsage             = "2.5.29.37";
    public const String FreshestCRL                  = "2.5.29.46";
}