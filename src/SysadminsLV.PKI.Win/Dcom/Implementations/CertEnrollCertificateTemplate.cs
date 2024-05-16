using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Interop.CERTENROLLLib;
using PKI.CertificateTemplates;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils;
using SysadminsLV.PKI.Utils.CLRExtensions;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;

namespace SysadminsLV.PKI.Dcom.Implementations;

/// <summary>
/// Represents CertEnroll-based implementation of <see cref="IAdcsCertificateTemplate"/>.
/// </summary>
public class CertEnrollCertificateTemplate : IAdcsCertificateTemplate {
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
    /// Initializes a new instance of <strong>CertEnrollCertificateTemplate</strong> class from an <see cref="IX509CertificateTemplate"/> COM interface.
    /// </summary>
    /// <param name="template">An instance of <see cref="IX509CertificateTemplate"/> COM interface.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>template</strong> parameter is null.
    /// </exception>
    public CertEnrollCertificateTemplate(IX509CertificateTemplate template) {
        if (template == null) {
            throw new ArgumentNullException(nameof(template));
        }

        CommonName = template.GetScalarValue<String>(EnrollmentTemplateProperty.TemplatePropCommonName);
        DisplayName = template.GetScalarValue<String>(EnrollmentTemplateProperty.TemplatePropFriendlyName);
        Oid = template.GetScalarValue<IObjectId>(EnrollmentTemplateProperty.TemplatePropOID).Value;
        SchemaVersion = template.GetInt32(EnrollmentTemplateProperty.TemplatePropSchemaVersion);
        MajorVersion = template.GetInt32(EnrollmentTemplateProperty.TemplatePropMajorRevision);
        MinorVersion = template.GetInt32(EnrollmentTemplateProperty.TemplatePropMinorRevision);
        _validityPeriod.AddRange(BitConverter.GetBytes(template.GetInt64(EnrollmentTemplateProperty.TemplatePropValidityPeriod, 99)));
        _renewalPeriod.AddRange(BitConverter.GetBytes(template.GetInt64(EnrollmentTemplateProperty.TemplatePropRenewalPeriod, 99)));
        Flags = template.GetEnum<CertificateTemplateFlags>(EnrollmentTemplateProperty.TemplatePropGeneralFlags);
        SubjectNameFlags = template.GetEnum<CertificateTemplateNameFlags>(EnrollmentTemplateProperty.TemplatePropSubjectNameFlags);
        EnrollmentFlags = template.GetEnum<CertificateTemplateEnrollmentFlags>(EnrollmentTemplateProperty.TemplatePropEnrollmentFlags);
        RASignatureCount = template.GetInt32(EnrollmentTemplateProperty.TemplatePropRASignatureCount);
        _raAppPolicies.AddRange(template.GetScalarValue<IObjectIds>(EnrollmentTemplateProperty.TemplatePropRAEKUs, new CObjectIdsClass()).Cast<IObjectId>().Select(x => x.Value));
        _raCertPolicies.AddRange(template.GetScalarValue<IObjectIds>(EnrollmentTemplateProperty.TemplatePropRACertificatePolicies, new CObjectIdsClass()).Cast<IObjectId>().Select(x => x.Value));
        CryptPrivateKeyFlags = template.GetEnum<PrivateKeyFlags>(EnrollmentTemplateProperty.TemplatePropPrivateKeyFlags);
        CryptKeySpec = template.GetEnum<X509KeySpecFlags>(EnrollmentTemplateProperty.TemplatePropKeySpec);
        CryptSymmetricKeyLength = template.GetInt32(EnrollmentTemplateProperty.TemplatePropSymmetricKeyLength);
        CryptSymmetricAlgorithm = template.GetScalarValue<String>(EnrollmentTemplateProperty.TemplatePropSymmetricAlgorithm);
        CryptPublicKeyLength = template.GetInt32(EnrollmentTemplateProperty.TemplatePropMinimumKeySize);
        CryptPublicKeyAlgorithm = template.GetScalarValue(EnrollmentTemplateProperty.TemplatePropAsymmetricAlgorithm, "RSA");
        CryptHashAlgorithm = template.GetScalarValue(EnrollmentTemplateProperty.TemplatePropHashAlgorithm, "SHA1");
        CryptCngKeyUsages = template.GetEnum<CngKeyUsages>(EnrollmentTemplateProperty.TemplatePropKeyUsage);
        CryptPrivateKeySDDL = template.GetScalarValue<String>(EnrollmentTemplateProperty.TemplatePropKeySecurityDescriptor);
        _cryptCspList.AddRange(template.GetCollectionValue<String>(EnrollmentTemplateProperty.TemplatePropCryptoProviders));
        _supersededTemplates.AddRange(template.GetCollectionValue<String>(EnrollmentTemplateProperty.TemplatePropSupersede));
        _eku.AddRange(template.GetScalarValue<IObjectIds>(EnrollmentTemplateProperty.TemplatePropEKUs, new CObjectIdsClass()).Cast<IObjectId>().Select(x => x.Value));
        foreach (IObjectId policyOid in template.GetScalarValue<IObjectIds>(EnrollmentTemplateProperty.TemplatePropCertificatePolicies, new CObjectIdsClass())) {
            var certPolicy = new CertificateTemplateCertificatePolicy(policyOid.Value);
            var oid2 = new Oid2(policyOid.Value, OidGroup.Policy, true);
            try {
                certPolicy.PolicyLocation = new Uri(oid2.GetCPSLinks()[0]);
            } catch { }
            _certPolicies.Add(certPolicy);
        }
        IX509Extensions extensions = template.GetScalarValue<IX509Extensions>(EnrollmentTemplateProperty.TemplatePropExtensions, new CX509Extensions());
        foreach (IX509Extension extension in extensions) {
            if (extension.Critical) {
                _criticalExtensions.Add(extension.ObjectId.Value);
            }

            switch (extension.ObjectId.Value) {
                case X509ExtensionOid.BasicConstraints:
                    var bc = new CX509ExtensionBasicConstraintsClass();
                    bc.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, extension.RawData[EncodingType.XCN_CRYPT_STRING_BASE64]);
                    ExtBasicConstraintsPathLength = bc.PathLenConstraint;
                    CryptographyUtils.ReleaseCom(bc);
                    break;
                case X509ExtensionOid.KeyUsage:
                    var ku = new CX509ExtensionKeyUsageClass();
                    ku.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, extension.RawData[EncodingType.XCN_CRYPT_STRING_BASE64]);
                    ExtKeyUsages = (X509KeyUsageFlags)ku.KeyUsage;
                    CryptographyUtils.ReleaseCom(ku);
                    break;
            }
        }
    }

    /// <inheritdoc />
    public String CommonName { get; }
    /// <inheritdoc />
    public String DisplayName { get; }
    /// <inheritdoc />
    public String Oid { get; }
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
    public Int32 RASignatureCount { get; }
    /// <inheritdoc />
    public String[] RAApplicationPolicies => [.. _raAppPolicies];
    /// <inheritdoc />
    public String[] RACertificatePolicies => [.. _raCertPolicies];
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
    public String CryptPublicKeyAlgorithm { get; }
    /// <inheritdoc />
    public String CryptHashAlgorithm { get; }
    /// <inheritdoc />
    public String[] CryptSupportedProviders => [.. _cryptCspList];
    /// <inheritdoc />
    public String CryptPrivateKeySDDL { get; }
    /// <inheritdoc />
    public String[] SupersededTemplates => [.. _supersededTemplates];
    /// <inheritdoc />
    public String[] CriticalExtensions => [.. _criticalExtensions];
    /// <inheritdoc />
    public String[] ExtEKU => [.. _eku];
    /// <inheritdoc />
    public ICertificateTemplateCertificatePolicy[] ExtCertPolicies => [.. _certPolicies];
    /// <inheritdoc />
    public Int32 ExtBasicConstraintsPathLength { get; } = -1;
    /// <inheritdoc />
    public X509KeyUsageFlags ExtKeyUsages { get; }
    /// <inheritdoc />
    public CngKeyUsages CryptCngKeyUsages { get; }
    /// <inheritdoc />
    public IDictionary<String, Object> ExtendedProperties { get; } = new Dictionary<String, Object>();
}
