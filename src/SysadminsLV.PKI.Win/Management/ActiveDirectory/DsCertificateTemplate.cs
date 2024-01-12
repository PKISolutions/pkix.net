using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils;

namespace SysadminsLV.PKI.Management.ActiveDirectory;

/// <summary>
/// Represents an Active Directory-based implementation of <see cref="IAdcsCertificateTemplate"/> interface.
/// </summary>
public class DsCertificateTemplate : IAdcsCertificateTemplate {
    static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{DsUtils.ConfigContext}";
    readonly List<Byte> _validityPeriod = new();
    readonly List<Byte> _renewalPeriod = new();
    readonly List<String> _raAppPolicies = new();
    readonly List<String> _raCertPolicies = new();
    readonly List<String> _cryptCspList = new();
    readonly List<String> _supersededTemplates = new();
    readonly List<String> _criticalExtensions = new();
    readonly List<String> _eku = new();
    readonly List<ICertificateTemplateCertificatePolicy> _certPolicies = new();

    DsCertificateTemplate(String cn) {
        ExtendedProperties = new Dictionary<String, Object>(StringComparer.OrdinalIgnoreCase);
        CryptPublicKeyAlgorithm = AlgorithmOid.RSA;
        CryptHashAlgorithm = AlgorithmOid.SHA1;
        String ldapPath = DsUtils.Find(_baseDsPath, "cn", cn);
        if (String.IsNullOrEmpty(ldapPath)) {
            throw new ArgumentException("No certificate templates match search criteria.");
        }
        initializeFromDs(ldapPath);
    }

    /// <inheritdoc />
    public String CommonName { get; private set; }
    /// <inheritdoc />
    public String DisplayName { get; private set; }
    /// <inheritdoc />
    public String Oid { get; private set; }
    /// <inheritdoc />
    public String Description { get; private set; }
    /// <inheritdoc />
    public Int32 SchemaVersion { get; private set; }
    /// <inheritdoc />
    public Int32 MajorVersion { get; private set; }
    /// <inheritdoc />
    public Int32 MinorVersion { get; private set; }
    /// <inheritdoc />
    public Byte[] ValidityPeriod => _validityPeriod.ToArray();
    /// <inheritdoc />
    public Byte[] RenewalPeriod => _renewalPeriod.ToArray();
    /// <inheritdoc />
    public CertificateTemplateFlags Flags { get; private set; }
    /// <inheritdoc />
    public CertificateTemplateNameFlags SubjectNameFlags { get; private set; }
    /// <inheritdoc />
    public CertificateTemplateEnrollmentFlags EnrollmentFlags { get; private set; }
    /// <inheritdoc />
    public Int32 RASignatureCount { get; private set; }
    /// <inheritdoc />
    public String[] RAApplicationPolicies => _raAppPolicies.ToArray();
    /// <inheritdoc />
    public String[] RACertificatePolicies => _raCertPolicies.ToArray();
    /// <inheritdoc />
    public PrivateKeyFlags CryptPrivateKeyFlags { get; private set; }
    /// <inheritdoc />
    public Int32 CryptSymmetricKeyLength { get; private set; }
    /// <inheritdoc />
    public String CryptSymmetricAlgorithm { get; private set; }
    /// <inheritdoc />
    public Int32 CryptPublicKeyLength { get; private set; }
    /// <inheritdoc />
    public String CryptPublicKeyAlgorithm { get; private set; }
    /// <inheritdoc />
    public String CryptHashAlgorithm { get; private set; }
    /// <inheritdoc />
    public X509KeySpecFlags CryptKeySpec { get; private set; }
    /// <inheritdoc />
    public String[] CryptSupportedProviders => _cryptCspList.ToArray();
    /// <inheritdoc />
    public String[] SupersededTemplates => _supersededTemplates.ToArray();
    /// <inheritdoc />
    public String[] CriticalExtensions => _criticalExtensions.ToArray();
    /// <inheritdoc />
    public String[] ExtEKU => _eku.ToArray();
    /// <inheritdoc />
    public ICertificateTemplateCertificatePolicy[] ExtCertPolicies => _certPolicies.ToArray();
    /// <inheritdoc />
    public Int32 ExtBasicConstraintsPathLength { get; private set; }
    /// <inheritdoc />
    public X509KeyUsageFlags ExtKeyUsages { get; private set; }
    public IDictionary<String, Object> ExtendedProperties { get; }

    static DsPropertyCollection getDsEntryProperties(String ldapPath) {
        return DsUtils.GetEntryProperties(
            ldapPath,
            DsUtils.PropCN,
            DsUtils.PropDN,
            DsUtils.PropDisplayName,
            DsUtils.PropDescription,
            DsUtils.PropFlags,
            DsUtils.PropCpsOid,
            DsUtils.PropCertTemplateOid,
            DsUtils.PropLocalizedOid,
            DsUtils.PropPkiTemplateMajorVersion,
            DsUtils.PropPkiTemplateMinorVersion,
            DsUtils.PropPkiSchemaVersion,
            DsUtils.PropWhenChanged,
            DsUtils.PropPkiSubjectFlags,
            DsUtils.PropPkiEnrollFlags,
            DsUtils.PropPkiPKeyFlags,
            DsUtils.PropPkiNotAfter,
            DsUtils.PropPkiRenewalPeriod,
            DsUtils.PropPkiPathLength,
            DsUtils.PropCertTemplateEKU,
            DsUtils.PropPkiCertPolicy,
            DsUtils.PropPkiCriticalExt,
            DsUtils.PropPkiSupersede,
            DsUtils.PropPkiKeyCsp,
            DsUtils.PropPkiKeySize,
            DsUtils.PropPkiKeySpec,
            DsUtils.PropPkiKeySddl,
            DsUtils.PropPkiRaAppPolicy,
            DsUtils.PropPkiRaCertPolicy,
            DsUtils.PropPkiRaSignature,
            DsUtils.PropPkiAsymAlgo,
            DsUtils.PropPkiSymAlgo,
            DsUtils.PropPkiSymLength,
            DsUtils.PropPkiHashAlgo,
            DsUtils.PropPkiKeyUsage,
            DsUtils.PropPkiKeyUsageCng
        );
    }
    void initializeFromDs(String ldapPath) {
        DsPropertyCollection props = getDsEntryProperties(ldapPath);
        Flags = props.GetDsScalarValue<CertificateTemplateFlags>(DsUtils.PropFlags);
        CommonName = props.GetDsScalarValue<String>(DsUtils.PropCN);
        Oid = props.GetDsScalarValue<String>(DsUtils.PropCertTemplateOid);
        Description = props.GetDsScalarValue<String>(DsUtils.PropDescription);
        DisplayName = props.GetDsScalarValue<String>(DsUtils.PropDisplayName);
        SchemaVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiSchemaVersion);
        MajorVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMajorVersion);
        MinorVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMinorVersion);
        _validityPeriod.AddRange(props.GetDsScalarValue<Byte[]>(DsUtils.PropPkiNotAfter));
        _renewalPeriod.AddRange(props.GetDsScalarValue<Byte[]>(DsUtils.PropPkiRenewalPeriod));
        SubjectNameFlags = props.GetDsScalarValue<CertificateTemplateNameFlags>(DsUtils.PropPkiSubjectFlags);
        EnrollmentFlags = props.GetDsScalarValue<CertificateTemplateEnrollmentFlags>(DsUtils.PropPkiEnrollFlags);
        RASignatureCount = props.GetDsScalarValue<Int32>(DsUtils.PropPkiRaSignature);
        decodeRegistrationAuthority(props);
        CryptSymmetricKeyLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiSymLength);
        CryptSymmetricAlgorithm = props.GetDsScalarValue<String>(DsUtils.PropPkiSymAlgo);
        CryptPublicKeyLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiKeySize);
        CryptPrivateKeyFlags = props.GetDsScalarValue<PrivateKeyFlags>(DsUtils.PropPkiPKeyFlags);
        CryptKeySpec = props.GetDsScalarValue<X509KeySpecFlags>(DsUtils.PropPkiKeySpec);
        _cryptCspList.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiKeyCsp));
        _supersededTemplates.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiSupersede));
        _criticalExtensions.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiCriticalExt));
        _eku.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropCertTemplateEKU));
        foreach (String policyOid in props.GetDsCollectionValue<String>(DsUtils.PropPkiCertPolicy)) {
            var certPolicy = new CertificateTemplateCertificatePolicy(policyOid);
            var oid2 = new Oid2(policyOid, OidGroup.Policy, true);
            try {
                certPolicy.PolicyLocation = new Uri(oid2.GetCPSLinks()[0]);
            } catch { }
            _certPolicies.Add(certPolicy);
        }
        ExtBasicConstraintsPathLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiPathLength);
        Byte[] keyUsagesBytes = props.GetDsCollectionValue<Byte>(DsUtils.PropPkiKeyUsage);
        ExtKeyUsages = (X509KeyUsageFlags)Convert.ToInt16(String.Join("", keyUsagesBytes.Select(x => $"{x:x2}").ToArray()), 16);
        ExtendedProperties.Add("LastWriteTime", props.GetDsScalarValue<DateTime>(DsUtils.PropWhenChanged));
        ExtendedProperties.Add("DistinguishedName", ldapPath.Replace("LDAP://", null));
    }

    void decodeRegistrationAuthority(DsPropertyCollection props) {
        if (RASignatureCount > 0) {
            _raCertPolicies.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiRaCertPolicy));
            String raAppPolicies = props.GetDsScalarValue<String>(DsUtils.PropPkiRaAppPolicy);
            if (raAppPolicies == null) {
                return;
            }
            if (raAppPolicies.Contains("`")) {
                String[] delimiter = { "`" };
                String[] strings = raAppPolicies.Split(delimiter, StringSplitOptions.RemoveEmptyEntries);
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
                _raAppPolicies.Add(raAppPolicies);
            }
        }
    }

    public static IAdcsCertificateTemplate FromCommonName(String cn) {
        return new DsCertificateTemplate(cn);
    }

    public static IEnumerable<IAdcsCertificateTemplate> GetAll() {
        foreach (DirectoryEntry dsEntry in DsUtils.GetChildItems(_baseDsPath)) {
            using (dsEntry) {
                yield return FromCommonName(dsEntry.Properties["cn"].Value.ToString());
            }
        }
    }
}
