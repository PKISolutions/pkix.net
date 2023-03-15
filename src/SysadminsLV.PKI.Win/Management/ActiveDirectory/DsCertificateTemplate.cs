using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using PKI.CertificateTemplates;
using PKI.Utils;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Management.ActiveDirectory;
class DsCertificateTemplate : ICertificateTemplateSource {
    static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{DsUtils.ConfigContext}";
    readonly List<Byte> _validityPeriod = new();
    readonly List<Byte> _renewalPeriod = new();
    readonly OidCollection _raCertPolicies = new();
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
    public OidCollection RACertificatePolicies => _raCertPolicies.Duplicate();
    public Int32 CryptKeyLength { get; private set; }
    public PrivateKeyFlags CryptPrivateKeyFlags { get; private set; }
    public X509KeySpecFlags CryptKeySpec { get; private set; }
    public String[] CryptSupportedProviders => _cryptCspList.ToArray();
    public String[] SupersededTemplates => _supersededTemplates.ToArray();
    public String[] CriticalExtensions => _criticalExtensions.ToArray();
    public String[] ExtEKU => _eku.ToArray();
    public Int32 ExtBasicConstraintsPathLength { get; private set; }
    public X509KeyUsageFlags ExtKeyUsages { get; private set; }

    static IDictionary<String, Object> getDsEntryProperties(String ldapPath) {
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
        IDictionary<String, Object> props = getDsEntryProperties(ldapPath);
        Flags = (CertificateTemplateFlags)props[DsUtils.PropFlags];
        Name = (String)props[DsUtils.PropCN];
        Oid = (String)props[DsUtils.PropCertTemplateOid];
        DisplayName = (String)props[DsUtils.PropDisplayName];
        SchemaVersion = (Int32)props[DsUtils.PropPkiSchemaVersion];
        MajorVersion = (Int32)props[DsUtils.PropPkiTemplateMajorVersion];
        MinorVersion = (Int32)props[DsUtils.PropPkiTemplateMinorVersion];
        _validityPeriod.AddRange((Byte[])props[DsUtils.PropPkiNotAfter]);
        _renewalPeriod.AddRange((Byte[])props[DsUtils.PropPkiRenewalPeriod]);
        SubjectNameFlags = (CertificateTemplateNameFlags)props[DsUtils.PropPkiSubjectFlags];
        EnrollmentFlags = (CertificateTemplateEnrollmentFlags)props[DsUtils.PropPkiEnrollFlags];
        decodeRegistrationAuthority(props);
        CryptKeyLength = (Int32)props[DsUtils.PropPkiKeySize];
        CryptPrivateKeyFlags = (PrivateKeyFlags)props[DsUtils.PropPkiPKeyFlags];
        CryptKeySpec = (X509KeySpecFlags)(Int32)props[DsUtils.PropPkiKeySpec];
        readCsp(props);
        readSupersededTemplates(props);
        readCriticalExtensions(props);
        readEKU(props);
        ExtBasicConstraintsPathLength = (Int32)props[DsUtils.PropPkiPathLength];
        readKeyUsage(props);
    }

    void decodeRegistrationAuthority(IDictionary<String, Object> props) {
        RASignatureCount = (Int32)props[DsUtils.PropPkiRaSignature];
        if (RASignatureCount > 0) {
            readRaPolicies(props);
            String raAppPolicies = (String)props[DsUtils.PropPkiRaAppPolicy];
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
    void readRaPolicies(IDictionary<String, Object> props) {
        try {
            Object[] RaObject = (Object[])props[DsUtils.PropPkiRaCertPolicy];
            if (RaObject != null) {
                foreach (Object obj in RaObject) {
                    _raCertPolicies.Add(new Oid(obj.ToString()));
                }
            }
        } catch {
            String RaString = (String)props[DsUtils.PropPkiRaCertPolicy];
            _raCertPolicies.Add(new Oid(RaString));
        }
    }
    void readCsp(IDictionary<String, Object> props) {
        try {
            Object[] cspObject = (Object[])props[DsUtils.PropPkiKeyCsp];
            if (cspObject != null) {
                _cryptCspList.AddRange(cspObject.Select(csp => Regex.Replace(csp.ToString(), "^\\d+,", String.Empty)));
            }
        } catch {
            String cspString = (String)props[DsUtils.PropPkiKeyCsp];
            _cryptCspList.Add(Regex.Replace(cspString, "^\\d+,", String.Empty));
        }
    }
    void readSupersededTemplates(IDictionary<String, Object> props) {
        try {
            Object[] templates = (Object[])props[DsUtils.PropPkiSupersede];
            if (templates != null) {
                _supersededTemplates.AddRange(templates.Cast<String>());
            }
        } catch {
            _supersededTemplates.Add((String)props[DsUtils.PropPkiSupersede]);
        }
    }
    void readCriticalExtensions(IDictionary<String, Object> props) {
        try {
            Object[] oids = (Object[])props[DsUtils.PropPkiCriticalExt];
            if (oids == null) { return; }
            foreach (Object oid in oids) {
                _criticalExtensions.Add((String)oid);
            }
        } catch {
            _criticalExtensions.Add((String)props[DsUtils.PropPkiCriticalExt]);
        }
    }
    void readEKU(IDictionary<String, Object> props) {
        try {
            Object[] EkuObject = (Object[])props[DsUtils.PropCertTemplateEKU];
            if (EkuObject != null) {
                foreach (Object item in EkuObject) {
                    _eku.Add(item.ToString());
                }
            }
        } catch {
            String EkuString = (String)props[DsUtils.PropCertTemplateEKU];
            _eku.Add(EkuString);
        }
    }
    void readKeyUsage(IDictionary<String, Object> props) {
        // need to verify this
        ExtKeyUsages = props[DsUtils.PropPkiKeyUsage] is Byte[] ku
            ? (X509KeyUsageFlags)BitConverter.ToInt16(ku, 0)
            : X509KeyUsageFlags.None;
    }

    public static ICertificateTemplateSource FromCommonName(String cn) {
        return new DsCertificateTemplate(cn);
    }

    public static void GetAll() {
        foreach (DirectoryEntry dsEntry in DsUtils.GetChildItems(_baseDsPath)) {
            using (dsEntry) {
                FromCommonName(dsEntry.Properties["cn"].Value.ToString()));
            }
        }
    }
}
