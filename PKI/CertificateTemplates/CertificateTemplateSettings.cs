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
        readonly List<X509Extension> _exts = new List<X509Extension>();
        readonly OidCollection _ekus = new OidCollection();
        Int32 pathLength, pkf, schemaVersion, subjectFlags;

        internal CertificateTemplateSettings(IX509CertificateTemplate template) {
            InitializeCom(template);
            Cryptography = new CryptographyTemplateSettings(template);
            RegistrationAuthority = new IssuanceRequirements(template);
            CriticalExtensions = new OidCollection();
            KeyArchivalSettings = new KeyArchivalOptions(template);
        }
        internal CertificateTemplateSettings(IDictionary<String, Object> Entry) {
            _entry = Entry;
            Cryptography = new CryptographyTemplateSettings(_entry);
            RegistrationAuthority = new IssuanceRequirements(_entry);
            CriticalExtensions = new OidCollection();
            KeyArchivalSettings = new KeyArchivalOptions(_entry);
            m_initialize();
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
                if ((GeneralFlags & (Int32) CertificateTemplateFlags.IsCA) > 0) {
                    return CertTemplateSubjectType.CA;
                }
                if ((GeneralFlags & (Int32) CertificateTemplateFlags.MachineType) > 0) {
                    return CertTemplateSubjectType.Computer;
                }
                return (GeneralFlags & (Int32)CertificateTemplateFlags.IsCrossCA) > 0
                    ? CertTemplateSubjectType.CrossCA
                    : CertTemplateSubjectType.User;
            }
        }
        /// <summary>
        /// Gets or sets the way how the certificate's subject should be constructed.
        /// </summary>
        public CertificateTemplateNameFlags SubjectName => (CertificateTemplateNameFlags)subjectFlags;

        /// <summary>
        /// Gets or sets a list of OIDs that represent extended key usages (sertificate purposes).
        /// </summary>
        public OidCollection EnhancedKeyUsage => ((X509EnhancedKeyUsageExtension)Extensions?[X509ExtensionOid.EnhancedKeyUsage])?.EnhancedKeyUsages;

        /// <summary>
        /// Gets issuance policies designated to the template.
        /// </summary>
        public OidCollection CertificatePolicies { get; private set; }
        /// <summary>
        /// Gets the purpose of the certificate template's private key.
        /// </summary>
        public CertificateTemplatePurpose Purpose {
            get {
                if (
                    Cryptography.KeyUsage == X509KeyUsageFlags.DigitalSignature &&
                    Cryptography.KeySpec == X509KeySpecFlags.AT_KEYEXCHANGE &&
                    (EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0 &&
                    (EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
                    (pkf & (Int32)PrivateKeyFlags.RequireKeyArchival) == 0 &&
                    ((EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.RequireUserInteraction) != 0 ||
                    (pkf & (Int32)PrivateKeyFlags.RequireStrongProtection) != 0)
                ) { return CertificateTemplatePurpose.SignatureAndSmartCardLogon; }
                if (
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DigitalSignature) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.NonRepudiation) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) == 0 &&
                    (EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.RemoveInvalidFromStore) == 0
                    ) { return CertificateTemplatePurpose.Encryption; }
                if (
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.CrlSign) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyCertSign) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyAgreement) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.KeyEncipherment) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DataEncipherment) == 0 &&
                    ((Int32)Cryptography.KeyUsage & (Int32)X509KeyUsageFlags.DecipherOnly) == 0 &&
                    Cryptography.KeySpec == X509KeySpecFlags.AT_SIGNATURE &&
                    (EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.IncludeSymmetricAlgorithms) == 0 &&
                    (pkf & (Int32)PrivateKeyFlags.RequireKeyArchival) == 0
                    ) { return CertificateTemplatePurpose.Signature; }
                return CertificateTemplatePurpose.EncryptionAndSignature;
            }
        }
        /// <summary>
        /// Gets cryptogrpahy settings defined in the certificate template.
        /// </summary>
        public CryptographyTemplateSettings Cryptography { get; }
        /// <summary>
        /// Gets certificate extensions defined within current certificate template.
        /// </summary>
        public X509ExtensionCollection Extensions {
            get {
                X509ExtensionCollection extensions = new X509ExtensionCollection();
                foreach (X509Extension ext in _exts) { extensions.Add(ext); }
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
        public OidCollection CriticalExtensions { get; }
        /// <summary>
        /// Gets certificate template key archival encryption settings.
        /// </summary>
        public KeyArchivalOptions KeyArchivalSettings { get; }

        /// <summary>
        /// Stub.
        /// </summary>
        public Int32 EnrollmentOptions { get; private set; }

        /// <summary>
        /// Stub.
        /// </summary>
        public Int32 GeneralFlags { get; private set; }

        void m_initialize() {
            GeneralFlags = (Int32)_entry[DsUtils.PropFlags];
            subjectFlags = (Int32)_entry[DsUtils.PropPkiSubjectFlags];
            EnrollmentOptions = (Int32)_entry[DsUtils.PropPkiEnrollFlags];
            pkf = (Int32)_entry[DsUtils.PropPkiPKeyFlags];
            ValidityPeriod = get_validity((Byte[])_entry[DsUtils.PropPkiNotAfter]);
            RenewalPeriod = get_validity((Byte[])_entry[DsUtils.PropPkiRenewalPeriod]);
            pathLength = (Int32)_entry[DsUtils.PropPkiPathLength];
            if ((EnrollmentOptions & 2) > 0) { CAManagerApproval = true; }
            get_eku();
            get_certpolicies();
            get_criticals();
            get_superseded();
            get_extensions();
        }
        void InitializeCom(IX509CertificateTemplate template) {
            if (CryptographyUtils.TestOleCompat()) {
                GeneralFlags = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropGeneralFlags];
                EnrollmentOptions = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropEnrollmentFlags];
                subjectFlags = (Int32)template.Property[EnrollmentTemplateProperty.TemplatePropSubjectNameFlags];
                ValidityPeriod = get_validity(null, (Int64)template.Property[EnrollmentTemplateProperty.TemplatePropValidityPeriod]);
                RenewalPeriod = get_validity(null, (Int64)template.Property[EnrollmentTemplateProperty.TemplatePropRenewalPeriod]);
            } else {
                GeneralFlags = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropGeneralFlags]);
                EnrollmentOptions = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropEnrollmentFlags]);
                subjectFlags = unchecked((Int32)(UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropSubjectNameFlags]);
                ValidityPeriod = get_validity(null, Convert.ToInt64((UInt64)template.Property[EnrollmentTemplateProperty.TemplatePropValidityPeriod]));
                RenewalPeriod = get_validity(null, Convert.ToInt64((UInt64)template.Property[EnrollmentTemplateProperty.TemplatePropRenewalPeriod]));
            }
            try {
                SupersededTemplates = (String[])template.Property[EnrollmentTemplateProperty.TemplatePropSupersede];
            } catch { }
            List<X509Extension> exts2 = (from IX509Extension ext in (IX509Extensions) template.Property[EnrollmentTemplateProperty.TemplatePropExtensions] select new X509Extension(ext.ObjectId.Value, Convert.FromBase64String(ext.RawData[Interop.CERTENROLLLib.EncodingType.XCN_CRYPT_STRING_BASE64]), ext.Critical)).Select(CryptographyUtils.ConvertExtension).ToList();
            foreach (X509Extension ext in exts2) { _exts.Add(ext); }
        }

        static String get_validity(Byte[] rawData, Int64 fileTime = 0) {
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
            if (Value % 8760 == 0 && Value / 8760 >= 1) { output = Convert.ToString(Value / 8760) + " years"; }
            else if (Value % 720 == 0 && Value / 720 >= 1) { output = Convert.ToString(Value / 720) + " months"; }
            else if (Value % 168 == 0 && Value / 168 >= 1) { output = Convert.ToString(Value / 168) + " weeks"; }
            else if (Value % 24 == 0 && Value / 24 >= 1) { output = Convert.ToString(Value / 24) + " days"; }
            else if (Value % 1 == 0 && Value / 1 >= 1) { output = Convert.ToString(Value) + " hours"; }
            else { output = "0 hours"; }
            return output;
        }
        void get_eku() {
            try {
                Object[] EkuObject = (Object[])_entry[DsUtils.PropCertTemplateEKU];
                if (EkuObject != null) {
                    foreach (Object item in EkuObject) {
                        _ekus.Add(new Oid(item.ToString()));
                    }
                }
            } catch {
                String EkuString = (String)_entry[DsUtils.PropCertTemplateEKU];
                _ekus.Add(new Oid(EkuString));
            }
        }
        void get_certpolicies() {
            CertificatePolicies = new OidCollection();
            try {
                Object[] oids = (Object[])_entry[DsUtils.PropPkiCertPolicy];
                if (oids == null) { return; }
                foreach (Object oid in oids) {
                    CertificatePolicies.Add(new Oid((String)oid));
                }
            } catch {
                CertificatePolicies.Add(new Oid((String)_entry[DsUtils.PropPkiCertPolicy]));
            }
        }
        void get_criticals() {
            try {
                Object[] oids = (Object[])_entry[DsUtils.PropPkiCriticalExt];
                if (oids == null) { return; }
                foreach (Object oid in oids) {
                    CriticalExtensions.Add(new Oid((String)oid));
                }
            } catch {
                CriticalExtensions.Add(new Oid((String)_entry[DsUtils.PropPkiCriticalExt]));
            }
        }
        void get_superseded() {
            List<String> temps = new List<String>();
            try {
                Object[] templates = (Object[])_entry[DsUtils.PropPkiSupersede];
                if (templates != null) {
                    foreach (Object temp in templates) { temps.Add((String)temp); }
                }
            } catch {
                temps.Add((String)_entry[DsUtils.PropPkiSupersede]);
            }
            SupersededTemplates = temps.ToArray();
        }
        void get_extensions() {
            schemaVersion = (Int32)_entry[DsUtils.PropPkiSchemaVersion];
            foreach (String oid in new [] {
                X509ExtensionOid.KeyUsage,
                X509ExtensionOid.EnhancedKeyUsage,
                X509ExtensionOid.CertificatePolicies,
                X509ExtensionOid.CertTemplateInfoV2,
                X509ExtensionOid.BasicConstraints,
                X509ExtensionOid.OcspRevNoCheck}) {
                switch (oid) {
                    case X509ExtensionOid.KeyUsage:
                        _exts.Add(new X509KeyUsageExtension(Cryptography.KeyUsage, test_critical(X509ExtensionOid.KeyUsage)));
                        break;
                    case X509ExtensionOid.EnhancedKeyUsage:
                        if (_ekus.Count == 0) { break; }
                        _exts.Add(new X509EnhancedKeyUsageExtension(_ekus, test_critical(X509ExtensionOid.EnhancedKeyUsage)));
                        _exts.Add(new X509ApplicationPoliciesExtension(_ekus, test_critical(X509ExtensionOid.ApplicationPolicies)));
                        break;
                    case X509ExtensionOid.CertificatePolicies:
                        if (CertificatePolicies.Count > 0) {
                            X509CertificatePolicyCollection policies = new X509CertificatePolicyCollection();
                            foreach (Oid poloid in CertificatePolicies) {
                                Oid2 oid2 = new Oid2(poloid.Value, OidGroupEnum.IssuancePolicy, true);
                                X509CertificatePolicy policy = new X509CertificatePolicy(poloid.Value);
                                try {
                                    policy.Add(new X509PolicyQualifier(oid2.GetCPSLinks()[0]));
                                } catch { }
                                policies.Add(policy);
                            }
                            _exts.Add(new X509CertificatePoliciesExtension(policies, test_critical(
                                X509ExtensionOid.CertificatePolicies)));
                        }
                        break;
                    case X509ExtensionOid.CertTemplateInfoV2:
                        if (schemaVersion == 1) {
                            _exts.Add(new X509Extension(new Oid(X509ExtensionOid.CertTemplateInfoV2), Asn1Utils.EncodeBMPString((String)_entry[DsUtils.PropCN]), test_critical(
                                X509ExtensionOid.CertTemplateInfoV2)));
                        } else {
                            Int32 major = (Int32)_entry[DsUtils.PropPkiTemplateMajorVersion];
                            Int32 minor = (Int32)_entry[DsUtils.PropPkiTemplateMinorVersion];
                            Oid tempoid = new Oid((String)_entry[DsUtils.PropCertTemplateOid]);
                            _exts.Add(new X509CertificateTemplateExtension(tempoid, major, minor));
                            _exts[_exts.Count - 1].Critical = test_critical(X509ExtensionOid.CertificateTemplate);
                        }
                        break;
                    case X509ExtensionOid.BasicConstraints:
                        if (
                            SubjectType == CertTemplateSubjectType.CA ||
                            SubjectType == CertTemplateSubjectType.CrossCA ||
                            (EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.BasicConstraintsInEndEntityCerts) != 0
                        ) {
                            Boolean isCA;
                            if (SubjectType == CertTemplateSubjectType.CA || SubjectType == CertTemplateSubjectType.CrossCA) {
                                isCA = true;
                            } else {
                                isCA = false;
                            }
                            Boolean hasConstraints = GetPathLengthConstraint() != -1;
                            _exts.Add(new X509BasicConstraintsExtension(isCA, hasConstraints, GetPathLengthConstraint(), test_critical(
                                X509ExtensionOid.BasicConstraints)));
                        }
                        break;
                    case X509ExtensionOid.OcspRevNoCheck:
                        if ((EnrollmentOptions & (Int32)CertificateTemplateEnrollmentFlags.IncludeOcspRevNoCheck) != 0) {
                            _exts.Add(new X509Extension(X509ExtensionOid.OcspRevNoCheck, new Byte[] { 5, 0 }, test_critical(
                                X509ExtensionOid.OcspRevNoCheck)));
                        }
                        break;
                }
            }
        }
        Boolean test_critical(String stroid) {
            return CriticalExtensions.Cast<Oid>().Any(oid => oid.Value == stroid);
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
