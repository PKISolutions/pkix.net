using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.CertificateTemplates;

interface ICertificateTemplateSource {
    String Name { get; }
    String DisplayName { get; }
    String Oid { get; }
    Int32 SchemaVersion { get; }
    Int32 MajorVersion { get; }
    Int32 MinorVersion { get; }
    Byte[] ValidityPeriod { get; }
    Byte[] RenewalPeriod { get; }
    CertificateTemplateFlags Flags { get; }
    CertificateTemplateNameFlags SubjectNameFlags { get; }
    CertificateTemplateEnrollmentFlags EnrollmentFlags { get; }
    Int32 RASignatureCount { get; }
    Oid RAApplicationPolicy { get; }
    OidCollection RACertificatePolicies { get; }
    Int32 CryptKeyLength { get; }
    PrivateKeyFlags CryptPrivateKeyFlags { get; }
    X509KeySpecFlags CryptKeySpec { get; }
    String[] CryptSupportedProviders { get; }
    String[] SupersededTemplates { get; }
    String[] CriticalExtensions { get; }
    String[] ExtEKU { get; }
    Int32 ExtBasicConstraintsPathLength { get; }
    X509KeyUsageFlags ExtKeyUsages { get; }
}