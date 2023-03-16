using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PKI.CertificateTemplates;
using PKI.Utils;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory;
public class DsCertificateTemplate : ICertificateTemplateSource {
    static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{DsUtils.ConfigContext}";
    readonly List<Byte> _validityPeriod = new();
    readonly List<Byte> _renewalPeriod = new();
    readonly List<String> _raCertPolicies = new();
    readonly List<String> _cryptCspList = new();
    readonly List<String> _supersededTemplates = new();
    readonly List<String> _criticalExtensions = new();
    readonly List<String> _eku = new();

    DsCertificateTemplate(String cn) {
        initializeFromDs($"CN={cn},{_baseDsPath}");
    }

    public String Name { get; private set; }
    public String DisplayName { get; private set; }
    public String Oid { get; private set; }
    public Int32 SchemaVersion { get; private set; }
    public Int32 MajorVersion { get; private set; }
    public Int32 MinorVersion { get; private set; }
    public Byte[] ValidityPeriod => _validityPeriod.ToArray();
    public Byte[] RenewalPeriod => _renewalPeriod.ToArray();
    public CertificateTemplateFlags Flags { get; private set; }
    public CertificateTemplateNameFlags SubjectNameFlags { get; private set; }
    public CertificateTemplateEnrollmentFlags EnrollmentFlags { get; private set; }
    public Int32 RASignatureCount { get; private set; }
    public Oid RAApplicationPolicy { get; private set; }
    public String[] RACertificatePolicies => _raCertPolicies.ToArray();
    public Int32 CryptKeyLength { get; private set; }
    public PrivateKeyFlags CryptPrivateKeyFlags { get; private set; }
    public X509KeySpecFlags CryptKeySpec { get; private set; }
    public String[] CryptSupportedProviders => _cryptCspList.ToArray();
    public String[] SupersededTemplates => _supersededTemplates.ToArray();
    public String[] CriticalExtensions => _criticalExtensions.ToArray();
    public String[] ExtEKU => _eku.ToArray();
    public Int32 ExtBasicConstraintsPathLength { get; private set; }
    public X509KeyUsageFlags ExtKeyUsages { get; private set; }

    static DsPropertyCollection getDsEntryProperties(String ldapPath) {
        return DsUtils.GetEntryProperties(
            ldapPath,
            DsUtils.PropCN,
            DsUtils.PropDN,
            DsUtils.PropDisplayName,
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
        Name = props.GetDsScalarValue<String>(DsUtils.PropCN);
        Oid = props.GetDsScalarValue<String>(DsUtils.PropCertTemplateOid);
        DisplayName = props.GetDsScalarValue<String>(DsUtils.PropDisplayName);
        SchemaVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiSchemaVersion);
        MajorVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMajorVersion);
        MinorVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMinorVersion);
        _validityPeriod.AddRange(props.GetDsScalarValue<Byte[]>(DsUtils.PropPkiNotAfter));
        _renewalPeriod.AddRange(props.GetDsScalarValue<Byte[]>(DsUtils.PropPkiRenewalPeriod));
        SubjectNameFlags = props.GetDsScalarValue<CertificateTemplateNameFlags>(DsUtils.PropPkiSubjectFlags);
        EnrollmentFlags = props.GetDsScalarValue<CertificateTemplateEnrollmentFlags>(DsUtils.PropPkiEnrollFlags);
        decodeRegistrationAuthority(props);
        CryptKeyLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiKeySize);
        CryptPrivateKeyFlags = props.GetDsScalarValue<PrivateKeyFlags>(DsUtils.PropPkiPKeyFlags);
        CryptKeySpec = props.GetDsScalarValue<X509KeySpecFlags>(DsUtils.PropPkiKeySpec);
        _cryptCspList.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiKeyCsp));
        _supersededTemplates.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiSupersede));
        _criticalExtensions.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiCriticalExt));
        _eku.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropCertTemplateEKU));
        ExtBasicConstraintsPathLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiPathLength);
        Byte[] keyUsagesBytes = props.GetDsCollectionValue<Byte>(DsUtils.PropPkiKeyUsage);
        ExtKeyUsages = (X509KeyUsageFlags)Convert.ToInt16(String.Join("", keyUsagesBytes.Select(x => $"{x:x2}").ToArray()), 16);
    }

    void decodeRegistrationAuthority(DsPropertyCollection props) {
        RASignatureCount = props.GetDsScalarValue<Int32>(DsUtils.PropPkiRaSignature);
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
                            RAApplicationPolicy = new Oid(strings[index + 2]);
                            break;
                    }
                }
            } else {
                RAApplicationPolicy = new Oid(raAppPolicies);
            }
        }
    }

    public static ICertificateTemplateSource FromCommonName(String cn) {
        return new DsCertificateTemplate(cn);
    }

    public static IEnumerable<ICertificateTemplateSource> GetAll() {
        foreach (DirectoryEntry dsEntry in DsUtils.GetChildItems(_baseDsPath)) {
            using (dsEntry) {
                yield return FromCommonName(dsEntry.Properties["cn"].Value.ToString());
            }
        }
    }
}
