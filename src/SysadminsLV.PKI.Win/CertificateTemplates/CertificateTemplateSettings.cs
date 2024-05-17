using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace PKI.CertificateTemplates;

/// <summary>
/// This class represents certificate template extended settings.
/// </summary>
public class CertificateTemplateSettings {
    readonly IAdcsCertificateTemplate _template;
    readonly List<X509Extension> _extensions = [];
    readonly List<Oid> _ekuList = [];
    readonly List<Oid> _criticalExtensions = [];
    readonly List<Oid> _certPolicies = [];

    internal CertificateTemplateSettings(IAdcsCertificateTemplate template) {
        _template = template;
        Cryptography = new CryptographyTemplateSettings(template);
        RegistrationAuthority = new IssuanceRequirements(template);
        KeyArchivalSettings = new KeyArchivalOptions(template);
        initialize();
    }

    /// <summary>
    /// Gets or sets the maximum validity period of the certificate.
    /// </summary>
    public String ValidityPeriod { get; private set; }
    /// <summary>
    /// Gets or sets the time before a certificate expires, during which time, clients need to send a certificate renewal request.
    /// </summary>
    public String RenewalPeriod { get; private set; }
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
    public CertificateTemplateNameFlags SubjectName => _template.SubjectNameFlags;

    /// <summary>
    /// Gets or sets a list of OIDs that represent extended key usages (certificate purposes).
    /// </summary>
    [Obsolete("Use 'Extensions' property instead.")]
    public OidCollection EnhancedKeyUsage {
        get {
            var oids = new OidCollection();
            _ekuList.ForEach(x => oids.Add(x));
            return oids;
        }
    }

    /// <summary>
    /// Gets issuance policies designated to the template.
    /// </summary>
    [Obsolete("Use 'Extensions' property instead.")]
    public OidCollection CertificatePolicies {
        get {
            var oids = new OidCollection();
            _certPolicies.ForEach(x => oids.Add(x));
            return oids;
        }
    }
    /// <summary>
    /// Gets the purpose of the certificate template's private key.
    /// </summary>
    public CertificateTemplatePurpose Purpose {
        get {
            if (
                Cryptography.KeyUsage == X509KeyUsageFlags.DigitalSignature &&
                Cryptography.KeySpec == X509KeySpecFlags.AT_KEYEXCHANGE &&
                (EnrollmentOptions & CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0 &&
                (EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
                (_template.CryptPrivateKeyFlags & PrivateKeyFlags.RequireKeyArchival) == 0 &&
                ((EnrollmentOptions & CertificateTemplateEnrollmentFlags.RequireUserInteraction) != 0 ||
                 (_template.CryptPrivateKeyFlags & PrivateKeyFlags.RequireStrongProtection) != 0)
            ) { return CertificateTemplatePurpose.SignatureAndSmartCardLogon; }
            if (
                (Cryptography.KeyUsage & X509KeyUsageFlags.DigitalSignature) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.NonRepudiation) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.CrlSign) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.KeyCertSign) == 0 &&
                (EnrollmentOptions & CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0
            ) { return CertificateTemplatePurpose.Encryption; }
            if (
                (Cryptography.KeyUsage & X509KeyUsageFlags.CrlSign) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.KeyCertSign) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.KeyAgreement) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.KeyEncipherment) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.DataEncipherment) == 0 &&
                (Cryptography.KeyUsage & X509KeyUsageFlags.DecipherOnly) == 0 &&
                Cryptography.KeySpec == X509KeySpecFlags.AT_SIGNATURE &&
                (EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
                (_template.CryptPrivateKeyFlags & PrivateKeyFlags.RequireKeyArchival) == 0
            ) { return CertificateTemplatePurpose.Signature; }
            return CertificateTemplatePurpose.EncryptionAndSignature;
        }
    }
    /// <summary>
    /// Gets cryptography settings defined in the certificate template.
    /// </summary>
    public CryptographyTemplateSettings Cryptography { get; }
    /// <summary>
    /// Gets certificate extensions defined within current certificate template.
    /// </summary>
    public X509ExtensionCollection Extensions {
        get {
            var extensions = new X509ExtensionCollection();
            _extensions.ForEach(x => extensions.Add(x));
            return extensions;
        }
    }
    /// <summary>
    /// Gets certificate template name list that is superseded by the current template.
    /// </summary>
    public String[] SupersededTemplates => _template.SupersededTemplates;
    /// <summary>
    /// Gets or sets whether the requests based on a referenced template are put to a pending state.
    /// </summary>
    [Obsolete("Use 'RegistrationAuthority.CAManagerApproval' property instead.")]
    public Boolean CAManagerApproval => RegistrationAuthority.CAManagerApproval;
    /// <summary>
    /// Gets registration authority requirements. These are number of authorized signatures and authorized certificate application and/or issuance
    /// policy requirements.
    /// </summary>
    public IssuanceRequirements RegistrationAuthority { get; }
    /// <summary>
    /// Gets a collection of critical extensions.
    /// </summary>
    [Obsolete("This property is obsolete. Use 'X509Extension.IsCritical' property in Extensions member.")]
    public OidCollection CriticalExtensions {
        get {
            var oids = new OidCollection();
            _extensions.Where(x => x.Critical).ToList().ForEach(x => oids.Add(x.Oid));

            return oids;
        }
    }
    /// <summary>
    /// Gets certificate template key archival encryption settings.
    /// </summary>
    public KeyArchivalOptions KeyArchivalSettings { get; }
    /// <summary>
    /// Stub.
    /// </summary>
    public CertificateTemplateEnrollmentFlags EnrollmentOptions { get; private set; }
    /// <summary>
    /// Stub.
    /// </summary>
    public CertificateTemplateFlags GeneralFlags { get; private set; }

    void initialize() {
        GeneralFlags = _template.Flags;
        EnrollmentOptions = _template.EnrollmentFlags;
        ValidityPeriod = readValidity(_template.ValidityPeriod);
        RenewalPeriod = readValidity(_template.RenewalPeriod);
        _ekuList.AddRange(_template.ExtensionEKU.Select(x => new Oid(x)));
        _certPolicies.AddRange(_template.ExtensionCertPolicies.Select(x => new Oid(x.PolicyID)));
        _criticalExtensions.AddRange(_template.CriticalExtensions.Select(x => new Oid(x)));
        readExtensions();
    }

    static String readValidity(Byte[] rawData) {
        Int64 fileTime = BitConverter.ToInt64(rawData, 0);

        return SysadminsLV.PKI.ADCS.ValidityPeriod.FromFileTime(fileTime).ValidityString;
    }
    void readExtensions() {
        foreach (String oid in new[] {
                                         X509ExtensionOid.CertTemplateInfoV2,
                                         X509ExtensionOid.EnhancedKeyUsage,
                                         X509ExtensionOid.CertificatePolicies,
                                         X509ExtensionOid.KeyUsage,
                                         X509ExtensionOid.BasicConstraints,
                                         X509ExtensionOid.OcspRevNoCheck}) {
            switch (oid) {
                case X509ExtensionOid.KeyUsage:
                    _extensions.Add(new X509KeyUsageExtension(Cryptography.KeyUsage, isExtensionCritical(X509ExtensionOid.KeyUsage)));
                    break;
                case X509ExtensionOid.EnhancedKeyUsage:
                    if (_ekuList.Count == 0) {
                        break;
                    }
                    var oidCollection = new OidCollection();
                    _ekuList.ForEach(x => oidCollection.Add(x));
                    _extensions.Add(new X509EnhancedKeyUsageExtension(oidCollection, isExtensionCritical(X509ExtensionOid.EnhancedKeyUsage)));
                    _extensions.Add(new X509ApplicationPoliciesExtension(oidCollection, isExtensionCritical(X509ExtensionOid.ApplicationPolicies)));
                    break;
                case X509ExtensionOid.CertificatePolicies:
                    if (_certPolicies.Count > 0) {
                        var policies = new X509CertificatePolicyCollection();
                        foreach (Oid policyOid in _certPolicies) {
                            var oid2 = new Oid2(policyOid.Value, OidGroup.Policy, true);
                            var policy = new X509CertificatePolicy(policyOid.Value);
                            try {
                                policy.Add(new X509PolicyQualifier(oid2.GetCPSLinks()[0]));
                            } catch { }
                            policies.Add(policy);
                        }
                        _extensions.Add(new X509CertificatePoliciesExtension(policies, isExtensionCritical(
                            X509ExtensionOid.CertificatePolicies)));
                    }
                    break;
                case X509ExtensionOid.CertTemplateInfoV2:
                    Boolean isCritical = isExtensionCritical(X509ExtensionOid.CertTemplateInfoV2);
                    if (_template.SchemaVersion == 1) {
                        _extensions.Add(new X509Extension(X509ExtensionOid.CertTemplateInfoV2, new Asn1BMPString(_template.CommonName).GetRawData(), isCritical));
                    } else {
                        var templateOid = new Oid(_template.Oid, _template.DisplayName);
                        var extension = new X509CertificateTemplateExtension(templateOid, _template.MajorVersion, _template.MinorVersion, false) {
                            Critical = isCritical
                        };
                        _extensions.Add(extension);
                    }
                    break;
                case X509ExtensionOid.BasicConstraints:
                    if (
                        SubjectType is CertTemplateSubjectType.CA or CertTemplateSubjectType.CrossCA ||
                        (EnrollmentOptions & CertificateTemplateEnrollmentFlags.BasicConstraintsInEndEntityCerts) != 0
                    ) {
                        Boolean isCA = SubjectType is CertTemplateSubjectType.CA or CertTemplateSubjectType.CrossCA;
                        Boolean hasConstraints = GetPathLengthConstraint() != -1;
                        _extensions.Add(new X509BasicConstraintsExtension(isCA, hasConstraints, GetPathLengthConstraint(), isExtensionCritical(
                            X509ExtensionOid.BasicConstraints)));
                    }
                    break;
                case X509ExtensionOid.OcspRevNoCheck:
                    if ((EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeOcspRevNoCheck) != 0) {
                        _extensions.Add(new X509Extension(X509ExtensionOid.OcspRevNoCheck, [5, 0], isExtensionCritical(
                            X509ExtensionOid.OcspRevNoCheck)));
                    }
                    break;
            }
        }
    }
    Boolean isExtensionCritical(String oid) {
        return _criticalExtensions.Any(x => x.Value == oid);
    }

    /// <summary>
    /// Gets path length restriction for the certificates issued by this template.
    /// For end-entity (non-CA) certificate, a zero is always returned. If the CA certificate
    /// cannot issue certificates to other CAs, the method returns zero. If there is no path length
    /// restrictions, a -1 is returned.
    /// </summary>
    /// <returns>
    /// A value that indicates how many additional CAs under this certificate may appear in the certificate chain.
    /// </returns>
    public Int32 GetPathLengthConstraint() {
        return _template.ExtensionBasicConstraintsPathLength;
    }
}