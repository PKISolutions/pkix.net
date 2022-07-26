using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Interop.CERTENROLLLib;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// This class represents certificate template extended settings.
    /// </summary>
    public class CertificateTemplateSettings {
        readonly IDictionary<String, Object> _entry;
        readonly List<X509Extension> _extensions = new List<X509Extension>();
        readonly List<Oid> _ekuList = new List<Oid>();
        readonly List<Oid> _criticalExtensions = new List<Oid>();
        readonly List<Oid> _certPolicies = new List<Oid>();
        Int32 pathLength, pkf, schemaVersion, subjectFlags;

        internal CertificateTemplateSettings(IX509CertificateTemplate template) {
            initializeFromCOM(template);
            Cryptography = new CryptographyTemplateSettings(template);
            RegistrationAuthority = new IssuanceRequirements(template);
            KeyArchivalSettings = new KeyArchivalOptions(template);
        }
        internal CertificateTemplateSettings(IDictionary<String, Object> Entry) {
            _entry = Entry;
            Cryptography = new CryptographyTemplateSettings(_entry);
            RegistrationAuthority = new IssuanceRequirements(_entry);
            KeyArchivalSettings = new KeyArchivalOptions(_entry);
            initializeFromDsEntry();
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
        public CertificateTemplateNameFlags SubjectName => (CertificateTemplateNameFlags)subjectFlags;

        /// <summary>
        /// Gets or sets a list of OIDs that represent extended key usages (certificate purposes).
        /// </summary>
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
                    (pkf & (Int32)PrivateKeyFlags.RequireKeyArchival) == 0 &&
                    ((EnrollmentOptions & CertificateTemplateEnrollmentFlags.RequireUserInteraction) != 0 ||
                    (pkf & (Int32)PrivateKeyFlags.RequireStrongProtection) != 0)
                ) { return CertificateTemplatePurpose.SignatureAndSmartCardLogon; }
                if (
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DigitalSignature) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.NonRepudiation) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) == 0 &&
                    (EnrollmentOptions & CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0
                    ) { return CertificateTemplatePurpose.Encryption; }
                if (
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyAgreement) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyEncipherment) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DataEncipherment) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DecipherOnly) == 0 &&
                    Cryptography.KeySpec == X509KeySpecFlags.AT_SIGNATURE &&
                    (EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
                    (pkf & (Int32)PrivateKeyFlags.RequireKeyArchival) == 0
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
                X509ExtensionCollection extensions = new X509ExtensionCollection();
                _extensions.ForEach(x => extensions.Add(x));
                return extensions;
            }
        }
        /// <summary>
        /// Gets certificate template name list that is superseded by the current template.
        /// </summary>
        public String[] SupersededTemplates { get; private set; }
        /// <summary>
        /// Gets or sets whether the requests based on a referenced template are put to a pending state.
        /// </summary>
        public Boolean CAManagerApproval { get; private set; }
        /// <summary>
        /// Gets registration authority requirements. These are number of authorized signatures and authorized certificate application and/or issuance
        /// policy requirements.
        /// </summary>
        public IssuanceRequirements RegistrationAuthority { get; }
        /// <summary>
        /// Gets a collection of critical extensions.
        /// </summary>
        public OidCollection CriticalExtensions {
            get {
                var oids = new OidCollection();
                _criticalExtensions.ForEach(x => oids.Add(x));
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

        void initializeFromDsEntry() {
            GeneralFlags = (CertificateTemplateFlags)_entry[DsUtils.PropFlags];
            subjectFlags = (Int32)_entry[DsUtils.PropPkiSubjectFlags];
            EnrollmentOptions = (CertificateTemplateEnrollmentFlags)_entry[DsUtils.PropPkiEnrollFlags];
            pkf = (Int32)_entry[DsUtils.PropPkiPKeyFlags];
            ValidityPeriod = readValidity((Byte[])_entry[DsUtils.PropPkiNotAfter]);
            RenewalPeriod = readValidity((Byte[])_entry[DsUtils.PropPkiRenewalPeriod]);
            pathLength = (Int32)_entry[DsUtils.PropPkiPathLength];
            if ((EnrollmentOptions & CertificateTemplateEnrollmentFlags.CAManagerApproval) > 0) {
                CAManagerApproval = true;
            }
            readEKU();
            readCertPolicies();
            readCriticalExtensions();
            readSuperseded();
            readExtensions();
        }
        void initializeFromCOM(IX509CertificateTemplate template) {
            if (CryptographyUtils.TestOleCompat()) {
                GeneralFlags = (CertificateTemplateFlags)template.Property[EnrollmentTemplateProperty.TemplatePropGeneralFlags];
                EnrollmentOptions = (CertificateTemplateEnrollmentFlags)template.Property[EnrollmentTemplateProperty.TemplatePropEnrollmentFlags];
                subjectFlags = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropSubjectNameFlags];
                ValidityPeriod = readValidity(null, (Int64)template.Property[EnrollmentTemplateProperty.TemplatePropValidityPeriod]);
                RenewalPeriod = readValidity(null, (Int64)template.Property[EnrollmentTemplateProperty.TemplatePropRenewalPeriod]);
            } else {
                GeneralFlags = (CertificateTemplateFlags)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropGeneralFlags]);
                EnrollmentOptions = (CertificateTemplateEnrollmentFlags)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropEnrollmentFlags]);
                subjectFlags = unchecked((Int32)(UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropSubjectNameFlags]);
                ValidityPeriod = readValidity(null, Convert.ToInt64((UInt64)template.Property[EnrollmentTemplateProperty.TemplatePropValidityPeriod]));
                RenewalPeriod = readValidity(null, Convert.ToInt64((UInt64)template.Property[EnrollmentTemplateProperty.TemplatePropRenewalPeriod]));
            }
            try {
                SupersededTemplates = (String[])template.Property[EnrollmentTemplateProperty.TemplatePropSupersede];
            } catch {
                SupersededTemplates = Array.Empty<String>();
            }
            List<X509Extension> exts2 = (from IX509Extension ext in (IX509Extensions)template.Property[EnrollmentTemplateProperty.TemplatePropExtensions] select new X509Extension(ext.ObjectId.Value, Convert.FromBase64String(ext.RawData[Interop.CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64]), ext.Critical)).Select(CryptographyUtils.ConvertExtension).ToList();
            foreach (X509Extension ext in exts2) { _extensions.Add(ext); }
        }

        static String readValidity(Byte[] rawData, Int64 fileTime = 0) {
            Int64 Value;
            String output;
            if (rawData != null) {
                Array.Reverse(rawData);
                StringBuilder SB = new StringBuilder();
                foreach (Byte item in rawData) { SB.Append($"{item:X2}"); }
                Value = (Int64)(Convert.ToInt64(SB.ToString(), 16) * -.0000001 / 3600);
            } else {
                Value = fileTime / 3600;
            }
            if (Value % 8760 == 0 && Value / 8760 >= 1) {
                output = Convert.ToString(Value / 8760) + " years";
            } else if (Value % 720 == 0 && Value / 720 >= 1) {
                output = Convert.ToString(Value / 720) + " months";
            } else if (Value % 168 == 0 && Value / 168 >= 1) {
                output = Convert.ToString(Value / 168) + " weeks";
            } else if (Value % 24 == 0 && Value / 24 >= 1) {
                output = Convert.ToString(Value / 24) + " days";
            } else if (Value % 1 == 0 && Value / 1 >= 1) {
                output = Convert.ToString(Value) + " hours";
            } else {
                output = "0 hours";
            }

            return output;
        }
        void readEKU() {
            try {
                Object[] EkuObject = (Object[])_entry[DsUtils.PropCertTemplateEKU];
                if (EkuObject != null) {
                    foreach (Object item in EkuObject) {
                        _ekuList.Add(new Oid(item.ToString()));
                    }
                }
            } catch {
                String EkuString = (String)_entry[DsUtils.PropCertTemplateEKU];
                _ekuList.Add(new Oid(EkuString));
            }
        }
        void readCertPolicies() {
            try {
                Object[] oids = (Object[])_entry[DsUtils.PropPkiCertPolicy];
                if (oids == null) { return; }
                foreach (Object oid in oids) {
                    _certPolicies.Add(new Oid((String)oid));
                }
            } catch {
                _certPolicies.Add(new Oid((String)_entry[DsUtils.PropPkiCertPolicy]));
            }
        }
        void readCriticalExtensions() {
            try {
                Object[] oids = (Object[])_entry[DsUtils.PropPkiCriticalExt];
                if (oids == null) { return; }
                foreach (Object oid in oids) {
                    _criticalExtensions.Add(new Oid((String)oid));
                }
            } catch {
                _criticalExtensions.Add(new Oid((String)_entry[DsUtils.PropPkiCriticalExt]));
            }
        }
        void readSuperseded() {
            List<String> temps = new List<String>();
            try {
                Object[] templates = (Object[])_entry[DsUtils.PropPkiSupersede];
                if (templates != null) {
                    temps.AddRange(templates.Cast<String>());
                }
            } catch {
                temps.Add((String)_entry[DsUtils.PropPkiSupersede]);
            }
            SupersededTemplates = temps.ToArray();
        }
        void readExtensions() {
            schemaVersion = (Int32)_entry[DsUtils.PropPkiSchemaVersion];
            foreach (String oid in new[] {
                X509ExtensionOid.KeyUsage,
                X509ExtensionOid.EnhancedKeyUsage,
                X509ExtensionOid.CertificatePolicies,
                X509ExtensionOid.CertTemplateInfoV2,
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
                        _extensions.Add(new X509EnhancedKeyUsageExtension(EnhancedKeyUsage, isExtensionCritical(X509ExtensionOid.EnhancedKeyUsage)));
                        _extensions.Add(new X509ApplicationPoliciesExtension(EnhancedKeyUsage, isExtensionCritical(X509ExtensionOid.ApplicationPolicies)));
                        break;
                    case X509ExtensionOid.CertificatePolicies:
                        if (_certPolicies.Count > 0) {
                            var policies = new X509CertificatePolicyCollection();
                            foreach (Oid policyOid in _certPolicies) {
                                var oid2 = new Oid2(policyOid.Value, OidGroupEnum.IssuancePolicy, true);
                                X509CertificatePolicy policy = new X509CertificatePolicy(policyOid.Value);
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
                        if (schemaVersion == 1) {
                            _extensions.Add(new X509Extension(new Oid(X509ExtensionOid.CertificateTemplate), Asn1Utils.EncodeBMPString((String)_entry[DsUtils.PropCN]), isCritical));
                        } else {
                            Int32 major = (Int32)_entry[DsUtils.PropPkiTemplateMajorVersion];
                            Int32 minor = (Int32)_entry[DsUtils.PropPkiTemplateMinorVersion];
                            var templateOid = new Oid((String)_entry[DsUtils.PropCertTemplateOid]);
                            var extension = new X509CertificateTemplateExtension(templateOid, major, minor) {
                                Critical = isCritical
                            };
                            _extensions.Add(extension);
                        }
                        break;
                    case X509ExtensionOid.BasicConstraints:
                        if (
                            SubjectType == CertTemplateSubjectType.CA ||
                            SubjectType == CertTemplateSubjectType.CrossCA ||
                            (EnrollmentOptions & CertificateTemplateEnrollmentFlags.BasicConstraintsInEndEntityCerts) > 0
                        ) {
                            Boolean isCA;
                            if (SubjectType == CertTemplateSubjectType.CA || SubjectType == CertTemplateSubjectType.CrossCA) {
                                isCA = true;
                            } else {
                                isCA = false;
                            }
                            Boolean hasConstraints = GetPathLengthConstraint() != -1;
                            _extensions.Add(new X509BasicConstraintsExtension(isCA, hasConstraints, GetPathLengthConstraint(), isExtensionCritical(
                                X509ExtensionOid.BasicConstraints)));
                        }
                        break;
                    case X509ExtensionOid.OcspRevNoCheck:
                        if ((EnrollmentOptions & CertificateTemplateEnrollmentFlags.IncludeOcspRevNoCheck) > 0) {
                            _extensions.Add(new X509Extension(X509ExtensionOid.OcspRevNoCheck, new Byte[] { 5, 0 }, isExtensionCritical(
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
            return pathLength;
        }
    }
}
