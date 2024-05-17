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
public sealed class DsCertificateTemplate : IAdcsCertificateTemplate {
    static readonly String _baseDsPath = $"CN=Certificate Templates, CN=Public Key Services, CN=Services,{DsUtils.ConfigContext}";
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
    /// Initializes a new instance of <see cref="DsCertificateTemplate"/> from search type and search value.
    /// </summary>
    /// <param name="findType">
    /// Specifies certificate template search type. The search type can be either:
    /// Name, DisplayName or OID.
    /// </param>
    /// <param name="findValue">
    /// Specifies search pattern for a type specified in <strong>findType</strong> argument.
    /// </param>
    /// <remarks>Wildcards are not allowed.</remarks>
    internal DsCertificateTemplate(String findType, String findValue) {
        ExtendedProperties = new Dictionary<String, Object>(StringComparer.OrdinalIgnoreCase);
        CryptPublicKeyAlgorithm = AlgorithmOid.RSA;
        CryptHashAlgorithm = AlgorithmOid.SHA1;
        if (!DsUtils.Ping()) {
            throw new Exception(ErrorHelper.E_DCUNAVAILABLE);
        }
        searchByQuery(findType, findValue);

    }

    /// <inheritdoc />
    public String CommonName { get; private set; }
    /// <inheritdoc />
    public String DisplayName { get; private set; }
    /// <inheritdoc />
    public String Oid { get; private set; }
    /// <inheritdoc />
    public Int32 SchemaVersion { get; private set; }
    /// <inheritdoc />
    public Int32 MajorVersion { get; private set; }
    /// <inheritdoc />
    public Int32 MinorVersion { get; private set; }
    /// <inheritdoc />
    public Byte[] ValidityPeriod => [.. _validityPeriod];
    /// <inheritdoc />
    public Byte[] RenewalPeriod => [.. _renewalPeriod];
    /// <inheritdoc />
    public CertificateTemplateFlags Flags { get; private set; }
    /// <inheritdoc />
    public CertificateTemplateNameFlags SubjectNameFlags { get; private set; }
    /// <inheritdoc />
    public CertificateTemplateEnrollmentFlags EnrollmentFlags { get; private set; }
    /// <inheritdoc />
    public Int32 RASignatureCount { get; private set; }
    /// <inheritdoc />
    public String[] RAApplicationPolicies => [.. _raAppPolicies];
    /// <inheritdoc />
    public String[] RACertificatePolicies => [.. _raCertPolicies];
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
    public CngKeyUsages CryptCngKeyUsages { get; set; }
    /// <inheritdoc />
    public String[] CryptSupportedProviders => [.. _cryptCspList];
    public String CryptPrivateKeySDDL { get; set; }
    /// <inheritdoc />
    public String[] SupersededTemplates => [.. _supersededTemplates];
    /// <inheritdoc />
    public String[] CriticalExtensions => [.. _criticalExtensions];
    /// <inheritdoc />
    public String[] ExtensionEKU => [.. _eku];
    /// <inheritdoc />
    public ICertificateTemplateCertificatePolicy[] ExtensionCertPolicies => [.. _certPolicies];
    /// <inheritdoc />
    public Int32 ExtensionBasicConstraintsPathLength { get; private set; }
    /// <inheritdoc />
    public X509KeyUsageFlags ExtensionKeyUsages { get; private set; }
    /// <inheritdoc />
    public IDictionary<String, Object> ExtendedProperties { get; }

    void searchByQuery(String findType, String findValue) {
        String ldapPath = findType.ToLower() switch {
            "name"        => DsUtils.Find(_baseDsPath, DsUtils.PropCN, findValue),
            "displayname" => DsUtils.Find(_baseDsPath, DsUtils.PropDisplayName, findValue),
            "oid"         => DsUtils.Find(_baseDsPath, DsUtils.PropCertTemplateOid, findValue),
            _             => throw new Exception("The value for 'findType' must be either 'Name', 'DisplayName' or 'OID'.")
        };

        if (String.IsNullOrWhiteSpace(ldapPath)) {
            throw new ArgumentException("No certificate templates match search criteria.");
        }

        initializeFromDs(ldapPath);
    }

    static DsPropertyCollection getDsEntryProperties(String ldapPath) {
        return DsUtils.GetEntryProperties(
            ldapPath,
            DsUtils.PropCN,
            DsUtils.PropDN,
            DsUtils.PropDisplayName,
            DsUtils.PropAcl,
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
        DisplayName = props.GetDsScalarValue<String>(DsUtils.PropDisplayName);
        SchemaVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiSchemaVersion);
        MajorVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMajorVersion);
        MinorVersion = props.GetDsScalarValue<Int32>(DsUtils.PropPkiTemplateMinorVersion);
        _validityPeriod.AddRange(props.GetDsScalarValue<Byte[]>(DsUtils.PropPkiNotAfter));
        _renewalPeriod.AddRange(props.GetDsScalarValue<Byte[]>(DsUtils.PropPkiRenewalPeriod));
        SubjectNameFlags = props.GetDsScalarValue<CertificateTemplateNameFlags>(DsUtils.PropPkiSubjectFlags);
        EnrollmentFlags = props.GetDsScalarValue<CertificateTemplateEnrollmentFlags>(DsUtils.PropPkiEnrollFlags);
        decodeRegistrationAuthority(props);
        CryptSymmetricKeyLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiSymLength);
        CryptSymmetricAlgorithm = props.GetDsScalarValue<String>(DsUtils.PropPkiSymAlgo);
        CryptPublicKeyLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiKeySize);
        CryptPrivateKeyFlags = props.GetDsScalarValue<PrivateKeyFlags>(DsUtils.PropPkiPKeyFlags);
        CryptKeySpec = props.GetDsScalarValue<X509KeySpecFlags>(DsUtils.PropPkiKeySpec);
        decodeProvList(props);
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
        ExtensionBasicConstraintsPathLength = props.GetDsScalarValue<Int32>(DsUtils.PropPkiPathLength);
        Byte[] keyUsagesBytes = props.GetDsCollectionValue<Byte>(DsUtils.PropPkiKeyUsage);
        ExtensionKeyUsages = (X509KeyUsageFlags)Convert.ToInt16(String.Join("", keyUsagesBytes.Reverse().Select(x => $"{x:x2}").ToArray()), 16);
        ExtendedProperties.Add(DsUtils.PropWhenChanged, props.GetDsScalarValue<DateTime>(DsUtils.PropWhenChanged));
        ExtendedProperties.Add(DsUtils.PropDN, ldapPath.Replace("LDAP://", null));
        ExtendedProperties.Add(DsUtils.PropAcl, props[DsUtils.PropAcl]);
    }

    void decodeProvList(DsPropertyCollection props) {
        IEnumerable<String> provList = props.GetDsCollectionValue<String>(DsUtils.PropPkiKeyCsp).OrderBy(x => x);
        foreach (String provName in provList) {
            _cryptCspList.Add(provName.Split(',')[1]);
        }
    }
    void decodeRegistrationAuthority(DsPropertyCollection props) {
        RASignatureCount = props.GetDsScalarValue<Int32>(DsUtils.PropPkiRaSignature);
        if (RASignatureCount > 0) {
            _raCertPolicies.AddRange(props.GetDsCollectionValue<String>(DsUtils.PropPkiRaCertPolicy));
        }
        String raAppPolicies = props.GetDsScalarValue<String>(DsUtils.PropPkiRaAppPolicy);
        if (String.IsNullOrEmpty(raAppPolicies)) {
            return;
        }
        if (raAppPolicies.Contains("`")) {
            String[] delimiter = ["`"];
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
                    case DsUtils.PropPkiKeySddl:
                        CryptPrivateKeySDDL = strings[index + 2];
                        break;
                    case DsUtils.PropPkiKeyUsageCng:
                        CryptCngKeyUsages = (CngKeyUsages)Convert.ToInt32(strings[index + 2]);
                        break;
                }
            }
        } else if (RASignatureCount > 0) {
            _raAppPolicies.Add(raAppPolicies);
        }
    }

    /// <summary>
    /// Returns an instance of <see cref="IAdcsCertificateTemplate"/> interface from template common name.
    /// </summary>
    /// <param name="cn">Template common name.</param>
    /// <returns>Instance of <see cref="IAdcsCertificateTemplate"/> interface.</returns>
    internal static IAdcsCertificateTemplate FromCommonName(String cn) {
        return new DsCertificateTemplate("Name", cn);
    }
    /// <summary>
    /// Creates a new instance of <strong>CertificateTemplate</strong> object from certificate template's display name.
    /// </summary>
    /// <param name="displayName">Certificate template's display/friendly name.</param>
    /// <returns>Certificate template object.</returns>
    internal static IAdcsCertificateTemplate FromDisplayName(String displayName) {
        return new DsCertificateTemplate("DisplayName", displayName);
    }
    /// <summary>
    /// Creates a new instance of <strong>CertificateTemplate</strong> object from certificate template's object identifier (OID).
    /// </summary>
    /// <param name="oid">Certificate template's dot-decimal object identifier.</param>
    /// <returns>Certificate template object.</returns>
    internal static IAdcsCertificateTemplate FromOid(String oid) {
        return new DsCertificateTemplate("OID", oid);
    }

    /// <summary>
    /// Returns a collection of certificate templates as <see cref="IAdcsCertificateTemplate"/> instances.
    /// </summary>
    /// <returns>A collection of certificate templates.</returns>
    internal static IEnumerable<IAdcsCertificateTemplate> GetAll() {
        if (!DsUtils.Ping()) {
            throw new Exception(ErrorHelper.E_DCUNAVAILABLE);
        }
        foreach (DirectoryEntry dsEntry in DsUtils.GetChildItems(_baseDsPath)) {
            using (dsEntry) {
                yield return FromCommonName(dsEntry.Properties["cn"].Value.ToString());
            }
        }
    }
}
