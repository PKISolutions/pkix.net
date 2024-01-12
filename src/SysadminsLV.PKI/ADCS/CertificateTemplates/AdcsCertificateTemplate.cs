using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.ADCS.CertificateTemplates;

/// <summary>
/// Represents Microsoft AD CS decoded certificate template.
/// </summary>
public class AdcsCertificateTemplate {
    readonly X509ExtensionCollection _extensions = new();
    readonly List<String> _supersedeTemplates = new();

    /// <summary>
    /// Initializes a new instance of <strong>AdcsCertificateTemplate</strong> class from certificate template information.
    /// </summary>
    /// <param name="template">Certificate template information.</param>
    /// <exception cref="ArgumentNullException"><strong>template</strong> parameter is null.</exception>
    public AdcsCertificateTemplate(IAdcsCertificateTemplate template) {
        if (template == null) {
            throw new ArgumentNullException(nameof(template));
        }

        Name = template.CommonName;
        DisplayName = template.DisplayName;
        Version = $"{template.MajorVersion}.{template.MinorVersion}";
        GeneralFlags = template.Flags;
        EnrollmentFlags = template.EnrollmentFlags;
        SubjectName = template.SubjectNameFlags;
        SchemaVersion = template.SchemaVersion;
        OID = new Oid(template.Oid, DisplayName);
        if (template.ExtendedProperties.TryGetValue("LastWriteTime", out Object value)) {
            LastWriteTime = value as DateTime?;
        }
        if (template.ExtendedProperties.TryGetValue("DistinguishedName", out value)) {
            DistinguishedName = value as String;
        }
        ValidityPeriod = ValidityPeriod.FromFileTime(template.ValidityPeriod);
        RenewalPeriod = ValidityPeriod.FromFileTime(template.RenewalPeriod);
        _supersedeTemplates.AddRange(template.SupersededTemplates);
        Cryptography = new CryptographyTemplateSettings(template);
        RegistrationAuthority = new CertificateTemplateRegistrationAuthority(template);
        buildExtensions(template);
    }

    /// <summary>
    /// Gets certificate template common name. Common names cannot contain the following characters: " + , ; &lt; = &gt;
    /// </summary>
    public String Name { get; }
    /// <summary>
    /// Gets certificate template display name. Display name has no character restrictions.
    /// </summary>
    public String DisplayName { get; }
    /// <summary>
    /// Gets certificate template internal version string. The version consist of two values separated by dot:
    /// major version and minor version. Any template changes causes internal version change.
    /// </summary>
    /// <remarks>Template internal version is not changed if you modify template ACL.</remarks>
    public String Version { get; }

    /// <summary>
    /// Gets certificate template schema version (also known as template version). The value can be either 1, 2, 3 or 4. For template support
    /// by CA version see <see cref="SupportedCA"/> property description.
    /// </summary>
    public Int32 SchemaVersion { get; }
    /// <summary>
    /// This flag indicates whether clients can perform autoenrollment for the specified template.
    /// </summary>
    public Boolean AutoenrollmentAllowed => SchemaVersion > 1 && (GeneralFlags & CertificateTemplateFlags.Autoenrollment) > 0;

    /// <summary>
    /// Gets certificate template's object identifier. Object identifiers are used to uniquely identify certificate template. While
    /// certificate template common and display names can be changed, OID remains the same. Once template is deleted from
    /// Active Directory, associated OID is removed too. Any new template (even if with the same name values) will have different
    /// OID value.
    /// </summary>
    public Oid OID { get; }
    /// <summary>
    /// Gets the timestamp when certificate template was edited last time. The value can be used for audit purposes.
    /// </summary>
    public DateTime? LastWriteTime { get; }
    /// <summary>
    /// Gets certificate template's full distinguished name (location address) in Active Directory.
    /// </summary>
    public String DistinguishedName { get; }
    /// <summary>
    /// Gets the minimum version of the Certification Authority that can use this template to issue certificates. The following table
    /// describes template support by CA version:
    /// <list type="table">
    /// <listheader>
    /// <term>Schema version</term>
    /// <description>Supported CA versions</description>
    /// </listheader>
    /// <item><term>1</term>
    /// <description><list type="bullet">
    /// <item>Windows 2000 Server</item>
    /// <item>Windows Server 2003 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// <item><term>2</term>
    /// <description><list type="bullet">
    /// <item>Windows Server 2003 Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// <item><term>3</term>
    /// <description><list type="bullet">
    /// <item>Windows Server 2008 Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2 Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// <item><term>4</term>
    /// <description><list type="bullet">
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Standard, Datacenter editions</item>
    /// <item>Windows Server 2019 Standard, Datacenter editions</item>
    /// <item>Windows Server 2022 Standard, Datacenter editions</item>
    /// </list></description>
    /// </item>
    /// </list>
    /// </summary>
    public String SupportedCA { get; private set; }
    /// <summary>
    /// Gets the minimum supported client that can enroll certificates based on this template.
    /// </summary>
    public String SupportedClient { get; private set; }
    /// <summary>
    /// Gets template validity period information.
    /// </summary>
    public ValidityPeriod ValidityPeriod { get; }
    /// <summary>
    /// Gets template autoenrollment renewal period information.
    /// </summary>
    public ValidityPeriod RenewalPeriod { get; }
    /// <summary>
    /// Gets or sets certificate's subject type. Can be either: Computer, User, CA or CrossCA.
    /// </summary>
    public CertTemplateSubjectType SubjectType {
        get {
            if ((GeneralFlags & CertificateTemplateFlags.IsCA) > 0) {
                return CertTemplateSubjectType.CA;
            }
            if ((GeneralFlags & CertificateTemplateFlags.MachineType) > 0) {
                return CertTemplateSubjectType.Computer;
            }
            return (GeneralFlags & CertificateTemplateFlags.IsCrossCA) > 0
                ? CertTemplateSubjectType.CrossCA
                : CertTemplateSubjectType.User;
        }
    }
    /// <summary>
    /// Gets or sets the way how the certificate's subject should be constructed.
    /// </summary>
    public CertificateTemplateNameFlags SubjectName { get; }
    /// <summary>
    /// Gets the purpose of the certificate template's private key.
    /// </summary>
    public CertificateTemplatePurpose Purpose {
        get {
            //if (
            //    Cryptography.KeyUsage == X509KeyUsageFlags.DigitalSignature &&
            //    Cryptography.KeySpec == X509KeySpecFlags.AT_KEYEXCHANGE &&
            //    (EnrollmentOptions & CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0 &&
            //    (EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
            //    (pkf & (Int32)PrivateKeyFlags.RequireKeyArchival) == 0 &&
            //    ((EnrollmentOptions & CertificateTemplateEnrollmentFlags.RequireUserInteraction) != 0 ||
            //     (pkf & (Int32)PrivateKeyFlags.RequireStrongProtection) != 0)
            //) { return CertificateTemplatePurpose.SignatureAndSmartCardLogon; }
            //if (
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DigitalSignature) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.NonRepudiation) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) == 0 &&
            //    (EnrollmentOptions & CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0
            //) { return CertificateTemplatePurpose.Encryption; }
            //if (
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyAgreement) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyEncipherment) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DataEncipherment) == 0 &&
            //    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DecipherOnly) == 0 &&
            //    Cryptography.KeySpec == X509KeySpecFlags.AT_SIGNATURE &&
            //    (EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
            //    (pkf & (Int32)PrivateKeyFlags.RequireKeyArchival) == 0
            //) { return CertificateTemplatePurpose.Signature; }
            return CertificateTemplatePurpose.EncryptionAndSignature;
        }
    }
    /// <summary>
    /// Gets certificate template name list that is superseded by the current template.
    /// </summary>
    public String[] SupersededTemplates => _supersedeTemplates.ToArray();
    /// <summary>
    /// Gets cryptography settings defined in the certificate template.
    /// </summary>
    public CryptographyTemplateSettings Cryptography { get; }
    /// <summary>
    /// Gets registration authority requirements. These are number of authorized signatures and authorized certificate application and/or issuance
    /// policy requirements.
    /// </summary>
    public CertificateTemplateRegistrationAuthority RegistrationAuthority { get; }
    /// <summary>
    /// Gets template general flags.
    /// </summary>
    public CertificateTemplateFlags GeneralFlags { get; }
    /// <summary>
    /// Gets template enrollment flags.
    /// </summary>
    public CertificateTemplateEnrollmentFlags EnrollmentFlags { get; }
    /// <summary>
    /// Gets certificate extensions defined within current certificate template.
    /// </summary>
    public X509ExtensionCollection Extensions => _extensions.Duplicate();

    #region Certificate extensions

    void buildExtensions(IAdcsCertificateTemplate template) {
        buildEkuExtension(template);
        buildBasicConstraintsExtension(template);
        buildTemplateExtension(template);
        buildCertPoliciesExtension(template);
        buildKeyUsagesExtension(template);
        buildOcspRevNoCheckExtension(template);
    }
    void buildEkuExtension(IAdcsCertificateTemplate template) {
        Boolean fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.EnhancedKeyUsage);
        var ekuOid = new OidCollection();
        foreach (String oid in template.ExtEKU) {
            ekuOid.Add(new Oid(oid));
        }
        _extensions.Add(new X509EnhancedKeyUsageExtension(ekuOid, fCritical));
        fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.ApplicationPolicies);
        _extensions.Add(new X509ApplicationPoliciesExtension(ekuOid, fCritical));
    }
    void buildBasicConstraintsExtension(IAdcsCertificateTemplate template) {
        if (
            SubjectType is CertTemplateSubjectType.CA or CertTemplateSubjectType.CrossCA ||
            (EnrollmentFlags & CertificateTemplateEnrollmentFlags.BasicConstraintsInEndEntityCerts) > 0
        ) {
            Boolean fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.BasicConstraints);
            Boolean isCA = SubjectType is CertTemplateSubjectType.CA or CertTemplateSubjectType.CrossCA;
            
            Boolean hasConstraints = isCA && template.ExtBasicConstraintsPathLength != -1;
            _extensions.Add(new X509BasicConstraintsExtension(isCA, hasConstraints, template.ExtBasicConstraintsPathLength, fCritical));
        }
    }
    void buildTemplateExtension(IAdcsCertificateTemplate template) {
        Boolean fCritical;
        if (template.SchemaVersion > 1) {
            fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.CertTemplateInfoV2);
            _extensions.Add(new X509CertificateTemplateExtension(OID, template.MajorVersion, template.MinorVersion, fCritical));
        } else {
            fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.CertificateTemplateName);
            _extensions.Add(new X509Extension(X509ExtensionOid.CertificateTemplateName, new Asn1BMPString(Name).GetRawData(), fCritical));
        }
    }
    void buildCertPoliciesExtension(IAdcsCertificateTemplate template) {
        if (template.ExtCertPolicies.Length == 0) {
            return;
        }
        Boolean fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.CertificatePolicies);
        var policies = new X509CertificatePolicyCollection();
        foreach (ICertificateTemplateCertificatePolicy policyObj in template.ExtCertPolicies) {
            var policy = new X509CertificatePolicy(policyObj.PolicyID);
            if (policyObj.PolicyLocation != null) {
                policy.Add(new X509PolicyQualifier(policyObj.PolicyLocation.AbsoluteUri.TrimEnd()));
            }
            policies.Add(policy);
        }
        _extensions.Add(new X509CertificatePoliciesExtension(policies, fCritical));
    }
    void buildKeyUsagesExtension(IAdcsCertificateTemplate template) {
        Boolean fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.KeyUsage);
        _extensions.Add(new X509KeyUsageExtension(template.ExtKeyUsages, fCritical));
    }
    void buildOcspRevNoCheckExtension(IAdcsCertificateTemplate template) {
        if ((EnrollmentFlags & CertificateTemplateEnrollmentFlags.IncludeOcspRevNoCheck) > 0) {
            Boolean fCritical = template.CriticalExtensions.Contains(X509ExtensionOid.OcspRevNoCheck);
            _extensions.Add(new X509Extension(X509ExtensionOid.OcspRevNoCheck, new Byte[] { 5, 0 }, fCritical));
        }
    }

    #endregion
}
