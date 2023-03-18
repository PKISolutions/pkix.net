using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateTemplates;
using PKI.Utils;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.CertificateServices;

/// <summary>
/// Represents local registry cache-based implementation of <see cref="IAdcsCertificateTemplate"/> interface.
/// </summary>
public class RegCertificateTemplate : IAdcsCertificateTemplate {
    readonly List<Byte> _validityPeriod = new();
    readonly List<Byte> _renewalPeriod = new();
    readonly List<String> _raAppPolicies = new();
    readonly List<String> _raCertPolicies = new();
    readonly List<String> _cryptCspList = new();
    readonly List<String> _supersededTemplates = new();
    readonly List<String> _criticalExtensions = new();
    readonly List<String> _eku = new();
    readonly List<String> _certPolicies = new();

    /// <summary>
    /// Initializes a new instance of <strong>RegCertificateTemplate</strong> class from template name.
    /// </summary>
    /// <param name="commonName"></param>
    /// <exception cref="ArgumentException"></exception>
    public RegCertificateTemplate(String commonName) {
        var regReader = new RegistryReader(@"SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache");
        if (!regReader.TestSubKeyExists(commonName)) {
            throw new ArgumentException($"Specified template '{commonName}' does not exist in local template cache.");
        }

        ExtendedProperties = new Dictionary<String, Object>(StringComparer.OrdinalIgnoreCase);
        CommonName = commonName;
        DisplayName = regReader.GetStringValue(DsUtils.PropDisplayName);
        Oid = regReader.GetMultiStringValue(DsUtils.PropCertTemplateOid)[0];
        SchemaVersion = regReader.GetDWordValue(DsUtils.PropPkiSchemaVersion);
        MajorVersion = regReader.GetDWordValue(DsUtils.PropPkiTemplateMajorVersion);
        MinorVersion = regReader.GetDWordValue(DsUtils.PropPkiTemplateMinorVersion);
        _validityPeriod.AddRange(regReader.GetBinaryValue("ValidityPeriod"));
        _renewalPeriod.AddRange(regReader.GetBinaryValue("RenewalOverlap"));
        Flags = regReader.GetEnumValue<CertificateTemplateFlags>(DsUtils.PropFlags);
        SubjectNameFlags = regReader.GetEnumValue<CertificateTemplateNameFlags>(DsUtils.PropPkiSubjectFlags);
        EnrollmentFlags = regReader.GetEnumValue<CertificateTemplateEnrollmentFlags>(DsUtils.PropPkiEnrollFlags);
        RASignatureCount = regReader.GetDWordValue(DsUtils.PropPkiRaSignature);
        decodeRegistrationAuthority(regReader);
        CryptPrivateKeyFlags = regReader.GetEnumValue<PrivateKeyFlags>(DsUtils.PropPkiPKeyFlags);
        CryptKeySpec = regReader.GetEnumValue<X509KeySpecFlags>("KeySpec");
        CryptSymmetricKeyLength = regReader.GetDWordValue(DsUtils.PropPkiSymLength, 0);
        CryptSymmetricAlgorithm = regReader.GetStringValue(DsUtils.PropPkiSymAlgo, null);
        CryptPublicKeyLength = regReader.GetDWordValue(DsUtils.PropPkiKeySize);
        _cryptCspList.AddRange(regReader.GetMultiStringValue("SupportedCSPs"));
        _supersededTemplates.AddRange(regReader.GetMultiStringValue(DsUtils.PropPkiSupersede));
        _criticalExtensions.AddRange(regReader.GetMultiStringValue("CriticalExtensions"));
        _eku.AddRange(regReader.GetMultiStringValue("ExtKeyUsageSyntax"));
        _certPolicies.AddRange(regReader.GetMultiStringValue(DsUtils.PropPkiCertPolicy));
        ExtBasicConstraintsPathLength = regReader.GetDWordValue("PathLen");
        Byte[] keyUsagesBytes = regReader.GetBinaryValue("KeyUsage");
        ExtKeyUsages = (X509KeyUsageFlags)Convert.ToInt16(String.Join("", keyUsagesBytes.Select(x => $"{x:x2}").ToArray()), 16);
    }

    /// <inheritdoc />
    public String CommonName { get; }
    /// <inheritdoc />
    public String DisplayName { get; }
    /// <inheritdoc />
    public String Oid { get; }
    /// <inheritdoc />
    public String Description { get; }
    /// <inheritdoc />
    public Int32 SchemaVersion { get; }
    /// <inheritdoc />
    public Int32 MajorVersion { get; }
    /// <inheritdoc />
    public Int32 MinorVersion { get; }
    /// <inheritdoc />
    public Byte[] ValidityPeriod => _validityPeriod.ToArray();
    /// <inheritdoc />
    public Byte[] RenewalPeriod => _renewalPeriod.ToArray();
    /// <inheritdoc />
    public CertificateTemplateFlags Flags { get; }
    /// <inheritdoc />
    public CertificateTemplateNameFlags SubjectNameFlags { get; }
    /// <inheritdoc />
    public CertificateTemplateEnrollmentFlags EnrollmentFlags { get; }
    /// <inheritdoc />
    public Int32 RASignatureCount { get; }
    /// <inheritdoc />
    public String[] RAApplicationPolicies => _raAppPolicies.ToArray();
    /// <inheritdoc />
    public String[] RACertificatePolicies => _raCertPolicies.ToArray();
    /// <inheritdoc />
    public PrivateKeyFlags CryptPrivateKeyFlags { get; }
    /// <inheritdoc />
    public X509KeySpecFlags CryptKeySpec { get; }
    /// <inheritdoc />
    public Int32 CryptSymmetricKeyLength { get; }
    /// <inheritdoc />
    public String CryptSymmetricAlgorithm { get; }
    /// <inheritdoc />
    public Int32 CryptPublicKeyLength { get; }
    /// <inheritdoc />
    public String CryptPublicKeyAlgorithm { get; private set; } = AlgorithmOid.RSA;
    /// <inheritdoc />
    public String CryptHashAlgorithm { get; private set; } = AlgorithmOid.SHA1;
    /// <inheritdoc />
    public String[] CryptSupportedProviders => _cryptCspList.ToArray();
    /// <inheritdoc />
    public String[] SupersededTemplates => _supersededTemplates.ToArray();
    /// <inheritdoc />
    public String[] CriticalExtensions => _criticalExtensions.ToArray();
    /// <inheritdoc />
    public String[] ExtEKU => _eku.ToArray();
    /// <inheritdoc />
    public String[] CertPolicies => _certPolicies.ToArray();
    /// <inheritdoc />
    public Int32 ExtBasicConstraintsPathLength { get; }
    /// <inheritdoc />
    public X509KeyUsageFlags ExtKeyUsages { get; }
    /// <inheritdoc />
    public IDictionary<String, Object> ExtendedProperties { get; }

    void decodeRegistrationAuthority(RegistryReader regReader) {
        if (RASignatureCount > 0) {
            _raCertPolicies.AddRange(regReader.GetMultiStringValue(DsUtils.PropPkiRaCertPolicy));
            String[] raAppPolicies = regReader.GetMultiStringValue(DsUtils.PropPkiRaAppPolicy);
            if (raAppPolicies == null || raAppPolicies.Length < 1) {
                return;
            }
            if (raAppPolicies[0].Contains("`")) {
                String[] delimiter = { "`" };
                String[] strings = raAppPolicies[0].Split(delimiter, StringSplitOptions.RemoveEmptyEntries);
                for (Int32 index = 0; index < strings.Length; index += 3) {
                    switch (strings[index]) {
                        case DsUtils.PropPkiRaAppPolicy:
                            _raAppPolicies.Add(strings[index + 2]);
                            break;
                        case DsUtils.PropPkiAsymAlgo:
                            CryptPublicKeyAlgorithm = strings[index + 2];
                            break;
                        case DsUtils.PropPkiHashAlgo:
                            CryptHashAlgorithm = strings[index + 2];
                            break;
                    }
                }
            } else {
                _raAppPolicies.AddRange(raAppPolicies);
            }
        }
    }
}
