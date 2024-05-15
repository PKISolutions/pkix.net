using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.CertificateServices;

/// <summary>
/// Represents local registry cache-based implementation of <see cref="IAdcsCertificateTemplate"/> interface.
/// </summary>
public class RegCertificateTemplate : IAdcsCertificateTemplate {
    readonly List<Byte> _validityPeriod = [];
    readonly List<Byte> _renewalPeriod = [];
    readonly List<String> _raAppPolicies = [];
    readonly List<String> _raCertPolicies = [];
    readonly List<String> _cryptCspList = [];
    readonly List<String> _supersededTemplates = [];
    readonly List<String> _criticalExtensions = [];
    readonly List<String> _eku = [];
    readonly List<ICertificateTemplateCertificatePolicy> _certPolicies = [];

    /// <summary>
    /// Initializes a new instance of <strong>RegCertificateTemplate</strong> class from template name.
    /// </summary>
    /// <param name="commonName">Template common name.</param>
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
        foreach (String policyOid in regReader.GetMultiStringValue(DsUtils.PropPkiCertPolicy)) {
            var certPolicy = new CertificateTemplateCertificatePolicy(policyOid);
            var oid2 = new Oid2(policyOid, OidGroup.Policy, true);
            try {
                certPolicy.PolicyLocation = new Uri(oid2.GetCPSLinks()[0]);
            } catch { }
            _certPolicies.Add(certPolicy);
        }
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
    public Byte[] ValidityPeriod => [.. _validityPeriod];
    /// <inheritdoc />
    public Byte[] RenewalPeriod => [.. _renewalPeriod];
    /// <inheritdoc />
    public CertificateTemplateFlags Flags { get; }
    /// <inheritdoc />
    public CertificateTemplateNameFlags SubjectNameFlags { get; }
    /// <inheritdoc />
    public CertificateTemplateEnrollmentFlags EnrollmentFlags { get; }
    /// <inheritdoc />
    public Int32 RASignatureCount { get; private set; }
    /// <inheritdoc />
    public String[] RAApplicationPolicies => [.. _raAppPolicies];
    /// <inheritdoc />
    public String[] RACertificatePolicies => [.. _raCertPolicies];
    /// <inheritdoc />
    public PrivateKeyFlags CryptPrivateKeyFlags { get; }
    public CngKeyUsages CryptCngKeyUsages { get; set; }
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
    public String[] CryptSupportedProviders => [.. _cryptCspList];
    public String CryptPrivateKeySDDL { get; set; }
    /// <inheritdoc />
    public String[] SupersededTemplates => [.. _supersededTemplates];
    /// <inheritdoc />
    public String[] CriticalExtensions => [.. _criticalExtensions];
    /// <inheritdoc />
    public String[] ExtEKU => [.. _eku];
    /// <inheritdoc />
    public ICertificateTemplateCertificatePolicy[] ExtCertPolicies => [.. _certPolicies];
    /// <inheritdoc />
    public Int32 ExtBasicConstraintsPathLength { get; }
    /// <inheritdoc />
    public X509KeyUsageFlags ExtKeyUsages { get; }
    /// <inheritdoc />
    public IDictionary<String, Object> ExtendedProperties { get; }

    void decodeRegistrationAuthority(RegistryReader regReader) {
        RASignatureCount = regReader.GetDWordValue(DsUtils.PropPkiRaSignature);
        if (RASignatureCount > 0) {
            _raCertPolicies.AddRange(regReader.GetMultiStringValue(DsUtils.PropPkiRaCertPolicy));
        }
        String[] raAppPolicies = regReader.GetMultiStringValue(DsUtils.PropPkiRaAppPolicy);
        if (raAppPolicies == null || raAppPolicies.Length < 1) {
            return;
        }
        if (raAppPolicies[0].Contains("`")) {
            String[] delimiter = ["`"];
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
                    case DsUtils.PropPkiKeySddl:
                        CryptPrivateKeySDDL = strings[index + 2];
                        break;
                    case DsUtils.PropPkiKeyUsageCng:
                        CryptCngKeyUsages = (CngKeyUsages)Convert.ToInt32(strings[index + 2]);
                        break;
                }
            }
        } else if (RASignatureCount > 0) {
            _raAppPolicies.AddRange(raAppPolicies);
        }
    }
}
