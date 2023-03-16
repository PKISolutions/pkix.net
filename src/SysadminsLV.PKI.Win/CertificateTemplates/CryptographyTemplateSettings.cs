using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Interop.CERTENROLLLib;
using PKI.Utils;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;

namespace PKI.CertificateTemplates {
    /// <summary>
    /// This class represents certificate template cryptography settings.
    /// </summary>
    public class CryptographyTemplateSettings {
        Int32 schemaVersion;
        readonly IDictionary<String, Object> _entry;

        internal CryptographyTemplateSettings(IX509CertificateTemplate template) {
            initializeFromCom(template);
        }
        internal CryptographyTemplateSettings(IDictionary<String, Object> Entry) {
            _entry = Entry;
            initializeFromDs();
        }

        /// <summary>
        /// Gets or sets a list of cryptographic service providers (CSPs) that are used to create the private key and public key.
        /// If the property is null, a client may use any CSP installed on the client system.
        /// </summary>
        [Obsolete("Use 'ProviderList' member instead.", true)]
        public String[] CSPList => ProviderList;
        /// <summary>
        /// Gets or sets a list of cryptographic service providers (CSPs) that are used to create the private key and public key.
        /// If the property is null, a client may use any CSP installed on the client system.
        /// </summary>
        public String[] ProviderList { get; private set; }
        /// <summary>
        /// Gets or sets key algorithm required by the certificate template.
        /// </summary>
        public Oid KeyAlgorithm { get; private set; }
        /// <summary>
        /// Gets or sets hash algorithm is used to sign request required by the certificate template.
        /// </summary>
        public Oid HashAlgorithm { get; private set; }
        /// <summary>
        /// Gets or sets the minimum size, in bits, of the public key that the client should create to obtain a certificate based
        /// on this template.
        /// </summary>
        public Int32 MinimalKeyLength { get; private set; }
        /// <summary>
        /// Gets or sets private key options.
        /// </summary>
        public PrivateKeyFlags PrivateKeyOptions { get; private set; }
        /// <summary>
        /// Indicates operations for which the private key can be used.
        /// </summary>
        public X509KeySpecFlags KeySpec { get; private set; }
        /// <summary>
        /// Gets key usages allowed by the template.
        /// </summary>
        public X509KeyUsageFlags KeyUsage { get; private set; }
        /// <summary>
        /// Gets key usages for CNG keys.
        /// </summary>
        public CngKeyUsages CNGKeyUsage { get; private set; }
        /// <summary>
        /// Gets the permissions when a private key is created
        /// </summary>
        public String PrivateKeySecuritySDDL { get; private set; }

        void initializeFromDs() {
            schemaVersion = (Int32)_entry[DsUtils.PropPkiSchemaVersion];
            KeyAlgorithm = new Oid("RSA");
            HashAlgorithm = new Oid("SHA1");
            MinimalKeyLength = (Int32)_entry[DsUtils.PropPkiKeySize];
            PrivateKeyOptions = (PrivateKeyFlags)_entry[DsUtils.PropPkiPKeyFlags];
            KeySpec = (X509KeySpecFlags)(Int32)_entry[DsUtils.PropPkiKeySpec];
            readCsp();
            readKeyUsages();
            String ap = (String)_entry[DsUtils.PropPkiRaAppPolicy];
            if (ap != null && ap.Contains("`")) {
                String[] delimiter = { "`" };
                String[] strings = ap.Split(delimiter, StringSplitOptions.RemoveEmptyEntries);
                for (Int32 index = 0; index < strings.Length; index += 3) {
                    switch (strings[index]) {
                        case DsUtils.PropPkiKeySddl: PrivateKeySecuritySDDL = strings[index + 2]; break;
                        case DsUtils.PropPkiAsymAlgo: KeyAlgorithm = new Oid(strings[index + 2]); break;
                        case DsUtils.PropPkiHashAlgo: HashAlgorithm = new Oid(strings[index + 2]); break;
                        case DsUtils.PropPkiKeyUsageCng: CNGKeyUsage = (CngKeyUsages)Convert.ToInt32(strings[index + 2]); break;
                    }
                }
            }

        }
        void readCsp() {
            var cspList = new List<String>();

            try {
                Object[] cspObject = (Object[])_entry[DsUtils.PropPkiKeyCsp];
                if (cspObject != null) {
                    cspList.AddRange(cspObject.Select(csp => Regex.Replace(csp.ToString(), "^\\d+,", String.Empty)));
                }
            } catch {
                String cspString = (String)_entry[DsUtils.PropPkiKeyCsp];
                cspList.Add(Regex.Replace(cspString, "^\\d+,", String.Empty));
            }
            ProviderList = cspList.ToArray();
        }
        void readKeyUsages() {
            if (!(_entry[DsUtils.PropPkiKeyUsage] is Byte[] ku)) {
                KeyUsage = X509KeyUsageFlags.None;
            } else {
                if (ku.Length == 1) {
                    KeyUsage = (X509KeyUsageFlags)ku[0];
                } else {
                    Array.Reverse(ku);
                    KeyUsage = (X509KeyUsageFlags)Convert.ToInt32(String.Join("", ku.Select(item => $"{item:x2}").ToArray()), 16);
                }
            }
            if (schemaVersion > 2) {
                X509KeyUsageFlags decryptionFlags =
                    X509KeyUsageFlags.DataEncipherment
                    | X509KeyUsageFlags.DecipherOnly
                    | X509KeyUsageFlags.EncipherOnly
                    | X509KeyUsageFlags.KeyEncipherment;

                if ((KeyUsage & decryptionFlags) == decryptionFlags) {
                    CNGKeyUsage |= CngKeyUsages.Decryption;
                }

                X509KeyUsageFlags signingFlags =
                    X509KeyUsageFlags.CrlSign
                    | X509KeyUsageFlags.DigitalSignature
                    | X509KeyUsageFlags.KeyCertSign;
                if ((KeyUsage & signingFlags) == signingFlags) {
                    CNGKeyUsage |= CngKeyUsages.Signing;
                }

                X509KeyUsageFlags agreementFlags = X509KeyUsageFlags.KeyAgreement;
                if ((KeyUsage & agreementFlags) == agreementFlags) {
                    CNGKeyUsage |= CngKeyUsages.KeyAgreement;
                }

                // all CNG usages enabled if at least one usage in every category is enabled.
                if ((KeyUsage & decryptionFlags) > 0
                    && (KeyUsage & signingFlags) > 0
                    && (KeyUsage & agreementFlags) > 0)
                {
                    CNGKeyUsage = CngKeyUsages.AllUsages;
                }
            }
        }
        void initializeFromCom(IX509CertificateTemplate template) {
            try {
                PrivateKeyOptions = (PrivateKeyFlags)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropPrivateKeyFlags]);
            } catch { }
            MinimalKeyLength = Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropMinimumKeySize]);
            KeySpec = (X509KeySpecFlags)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropKeySpec]);
            try {
                CNGKeyUsage = (CngKeyUsages)Convert.ToInt32((UInt32)template.Property[EnrollmentTemplateProperty.TemplatePropKeyUsage]);
            } catch { }
            try {
                ProviderList = (String[])template.Property[EnrollmentTemplateProperty.TemplatePropCryptoProviders];
            } catch { }
            try {
                KeyAlgorithm = new Oid((String)template.Property[EnrollmentTemplateProperty.TemplatePropAsymmetricAlgorithm]);
            } catch {
                KeyAlgorithm = new Oid("RSA");
            }
            try {
                HashAlgorithm = new Oid((String)template.Property[EnrollmentTemplateProperty.TemplatePropHashAlgorithm]);
            } catch {
                HashAlgorithm = new Oid("SHA1");
            }
            try {
                PrivateKeySecuritySDDL = (String)template.Property[EnrollmentTemplateProperty.TemplatePropKeySecurityDescriptor];
            } catch { }
        }

        /// <summary>
        /// Gets a textual representation of the certificate template cryptography settings.
        /// </summary>
        /// <returns>A textual representation of the certificate template cryptography settings</returns>
        public override String ToString() {
            String nl = Environment.NewLine;
            var SB = new StringBuilder();
            SB.Append(@"
[Cryptography Settings]
  CSP list: ");
            if (ProviderList == null) {
                SB.AppendLine("Any installed CSP");
            } else {
                SB.Append(nl);
                foreach (String csp in ProviderList) {
                    SB.AppendLine($"     {csp}");
                }
            }
            SB.AppendLine(@$"  Key Algorithm: {KeyAlgorithm.Format(true)}
  Hash Algorithm: {HashAlgorithm.Format(true)}
  Key Length: {MinimalKeyLength}
  Private key options: {PrivateKeyOptions}
  KeySpec: {KeySpec}
  CNG key usage: {CNGKeyUsage}");
            if (!String.IsNullOrEmpty(PrivateKeySecuritySDDL)) {
                SB.Append($"{nl}  Private key security descriptor: {PrivateKeySecuritySDDL}");
            }
            return SB.ToString().Trim();
        }
    }
}
