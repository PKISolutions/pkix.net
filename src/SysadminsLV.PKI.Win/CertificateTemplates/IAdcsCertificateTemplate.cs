using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.CertificateTemplates;

/// <summary>
/// Represents an Active Directory Certificate Services (AD CS) certificate template raw structure.
/// </summary>
public interface IAdcsCertificateTemplate {
    /// <summary>
    /// Gets template common name.
    /// </summary>
    String CommonName { get; }
    /// <summary>
    /// Gets template display name.
    /// </summary>
    String DisplayName { get; }
    /// <summary>
    /// Gets template object identifier.
    /// </summary>
    String Oid { get; }
    /// <summary>
    /// Gets template description.
    /// </summary>
    String Description { get; }
    /// <summary>
    /// Gets template schema version.
    /// </summary>
    Int32 SchemaVersion { get; }
    /// <summary>
    /// Gets template major version.
    /// </summary>
    Int32 MajorVersion { get; }
    /// <summary>
    /// Gets template minor validity.
    /// </summary>
    Int32 MinorVersion { get; }
    /// <summary>
    /// Gets validity period as <see cref="FILETIME"/> structure.
    /// </summary>
    Byte[] ValidityPeriod { get; }
    /// <summary>
    /// Gets renewal period as <see cref="FILETIME"/> structure.
    /// </summary>
    Byte[] RenewalPeriod { get; }
    /// <summary>
    /// Gets template general flags.
    /// </summary>
    CertificateTemplateFlags Flags { get; }
    /// <summary>
    /// Gets template subject name flags.
    /// </summary>
    CertificateTemplateNameFlags SubjectNameFlags { get; }
    /// <summary>
    /// Gets template enrollment flags
    /// </summary>
    CertificateTemplateEnrollmentFlags EnrollmentFlags { get; }
    /// <summary>
    /// Gets the number of request signatures required by template.
    /// </summary>
    Int32 RASignatureCount { get; }
    /// <summary>
    /// Gets a collection of enrollment agent application policies (EKUs) required by co-signing certificate.
    /// </summary>
    String[] RAApplicationPolicies { get; }
    /// <summary>
    /// Gets a collection of enrollment agent certificate policies (EKUs) required by co-signing certificate.
    /// </summary>
    String[] RACertificatePolicies { get; }
    /// <summary>
    /// Gets private key flags.
    /// </summary>
    PrivateKeyFlags CryptPrivateKeyFlags { get; }
    /// <summary>
    /// Gets private key's KeySpec.
    /// </summary>
    X509KeySpecFlags CryptKeySpec { get; }
    /// <summary>
    /// Gets symmetric algorithm key length.
    /// </summary>
    Int32 CryptSymmetricKeyLength { get; }
    /// <summary>
    /// Gets symmetric algorithm object identifier.
    /// </summary>
    String CryptSymmetricAlgorithm { get; }
    /// <summary>
    /// Gets minimum public key length.
    /// </summary>
    Int32 CryptPublicKeyLength { get; }
    /// <summary>
    /// Gets public key algorithm object identifier.
    /// </summary>
    String CryptPublicKeyAlgorithm { get; }
    /// <summary>
    /// Gets request hash algorithm.
    /// </summary>
    String CryptHashAlgorithm { get; }
    /// <summary>
    /// Gets a collection of allowed CSPs to use. Any CSP can be used if empty.
    /// </summary>
    String[] CryptSupportedProviders { get; }
    /// <summary>
    /// Gets a collection of superseded template common names.
    /// </summary>
    String[] SupersededTemplates { get; }
    /// <summary>
    /// Gets a collection of critical extension object identifiers.
    /// </summary>
    String[] CriticalExtensions { get; }
    /// <summary>
    /// Gets template application policies (EKUs).
    /// </summary>
    String[] ExtEKU { get; }
    /// <summary>
    /// Gets template certificate policies.
    /// </summary>
    String[] CertPolicies { get; }
    /// <summary>
    /// Gets Basic Constraints path length restriction. Applicable only for CA templates.
    /// </summary>
    Int32 ExtBasicConstraintsPathLength { get; }
    /// <summary>
    /// Gets template Key Usages.
    /// </summary>
    X509KeyUsageFlags ExtKeyUsages { get; }
    /// <summary>
    /// Gets a collection of custom template properties.
    /// </summary>
    IDictionary<String, Object> ExtendedProperties { get; }
}