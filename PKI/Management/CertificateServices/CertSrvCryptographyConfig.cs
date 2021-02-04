using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a Certification Authority cryptography configuration which determines which provider and algorithms to use when
    /// CA server signs certificates and certificate revocation lists (CRLs) and algorithm to use when CA creates CA exchange certificate
    /// and performs key archival.
    /// </summary>
    public class CertSrvCryptographyConfig : CertSrvConfig {
        const String S_NODE = "CSP";
        const String E_NODE = "EncryptionCSP";

        CspProviderInfo sigProv, encProv;
        Boolean alternateSignatureAlgorithm;
        Oid sigPubKeyAlg, encPubKeyAlg, hashingAlgorithm, encSymmetricAlg;
        Int32 encPubKeyLength;

        /// <summary>
        /// Initializes a new instance of <strong>CertSrvCryptographyConfig</strong> using Certification Authority computer name.
        /// </summary>
        /// <param name="computerName">NetBIOS or FQDN name.</param>
        public CertSrvCryptographyConfig(String computerName) : base(computerName) {
            ConfigManager.SetRootNode(true);
            readSigningCrypto();
            readEncryptionCrypto();
        }

        /// <summary>
        /// Gets or sets the public key algorithm (such as RSA, DSA or ECC) that is used for signing purposes.
        /// </summary>
        /// <remarks>Setter is ignored if provider specified in <see cref="EncryptionProvider"/> property is legacy provider.</remarks>
        public Oid SigningPublicKeyAlgorithm {
            get => sigPubKeyAlg;
            set {
                if (sigProv.IsLegacy && sigPubKeyAlg != null && value.Value == sigPubKeyAlg.Value) {
                    return;
                }
                sigPubKeyAlg = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the hashing algorithm that is used for signing purposes.
        /// </summary>
        public Oid HashingAlgorithm {
            get => hashingAlgorithm;
            set {
                if (hashingAlgorithm != null && value.Value == hashingAlgorithm.Value || !validateHashAlgorithm(value.Value)) {
                    return;
                }
                hashingAlgorithm = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the value that indicates whether the CA server supports alternate signature algorithms (PKCS#1 v2.1)
        /// </summary>
        /// <remarks>Setter is ignored if provider specified in <see cref="EncryptionProvider"/> property is legacy provider.</remarks>
        public Boolean AlternateSignatureAlgorithm {
            get => alternateSignatureAlgorithm;
            set {
                if (value == alternateSignatureAlgorithm && sigProv.IsLegacy) {
                    return;
                }
                alternateSignatureAlgorithm = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the provider name that is used by a Certification Authority installation.
        /// </summary>
        public CspProviderInfo SigningProvider {
            get => sigProv;
            set {
                if (value == null || sigProv.Name.Equals(value.Name, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }

                sigProv = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the public key algorithm (such as RSA, DSA or ECC) that is used to generate CA Exchange encryption certificate.
        /// Use <strong>ECDH_*</strong> for ECC-based public key. 
        /// </summary>
        /// <remarks>Setter is ignored if provider specified in <see cref="EncryptionProvider"/> property is legacy provider.</remarks>
        public Oid EncryptionPublicKeyAlgorithm {
            get => encPubKeyAlg;
            set {
                if (sigProv.IsLegacy && encPubKeyAlg != null && value.Value == encPubKeyAlg.Value) {
                    return;
                }
                encPubKeyAlg = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the CA Exchange public key length.
        /// </summary>
        /// <remarks>Setter is applicable only when CA uses RSA public key algorithm and setter value is ignored if CA uses ECC public key.</remarks>
        public Int32 EncryptionPublicKeySize {
            get => encPubKeyLength;
            set {
                if (encPubKeyLength == value) {
                    return;
                }

                encPubKeyLength = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the encryption symmetric algorithm used to perform key archival encryption.
        /// </summary>
        public Oid EncryptionAlgorithm {
            get => encSymmetricAlg;
            set {
                if (encSymmetricAlg != null && value.Value == encSymmetricAlg.Value || !validateEncAlgorithm(value.Value)) {
                    return;
                }
                encSymmetricAlg = value;
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets the length of symmetric encryption key. This property is automatically updated when setting <see cref="EncryptionAlgorithm"/> member.
        /// </summary>
        public Int32 SymmetricKeyLength { get; private set; }
        /// <summary>
        /// Gets or sets the provider name that is used by a Certification Authority installation.
        /// </summary>
        public CspProviderInfo EncryptionProvider {
            get => encProv;
            set {
                if (value == null || encProv.Name.Equals(value.Name, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }

                encProv = value;
                IsModified = true;
            }
        }

        void readSigningCrypto() {
            sigProv = CspProviderInfoCollection.GetProviderInfo(ConfigManager.GetStringEntry("Provider", S_NODE));
            sigPubKeyAlg = sigProv.IsLegacy
                ? new Oid(AlgorithmOid.RSA)
                : new Oid(ConfigManager.GetStringEntry("CNGPublicKeyAlgorithm", S_NODE));
            if (sigProv.IsLegacy) {
                // legacy
                hashingAlgorithm = getSigOidFromAlgId(ConfigManager.GetNumericEntry("HashAlgorithm", S_NODE));
            } else {
                // CNG
                hashingAlgorithm = new Oid(ConfigManager.GetStringEntry("CNGHashAlgorithm", S_NODE));
                alternateSignatureAlgorithm = ConfigManager.GetBooleanEntry("AlternateSignatureAlgorithm", S_NODE);
            }
        }
        void readEncryptionCrypto() {
            // encryption crypto
            encProv = CspProviderInfoCollection.GetProviderInfo(ConfigManager.GetStringEntry("Provider", E_NODE));
            if (encProv.IsLegacy) {
                // Win2k3
                encPubKeyAlg = new Oid(AlgorithmOid.RSA);
                encSymmetricAlg = new Oid(AlgorithmOid.TrippleDES);
            } else {
                encPubKeyAlg = new Oid(ConfigManager.GetStringEntry("CNGPublicKeyAlgorithm", E_NODE));
                encSymmetricAlg = new Oid(ConfigManager.GetStringEntry("CNGEncryptionAlgorithm", E_NODE));
            }

            encPubKeyLength = ConfigManager.GetNumericEntry("KeySize", E_NODE);
            SymmetricKeyLength = ConfigManager.GetNumericEntry("SymmetricKeySize", E_NODE);
        }

        static Oid getSigOidFromAlgId(Int32 algId) {
            switch (algId) {
                case 0x8001: return new Oid(AlgorithmOid.MD2);
                case 0x8003: return new Oid(AlgorithmOid.MD5);
                case 0x8004: return new Oid(AlgorithmOid.SHA1);
                case 0x8012: return new Oid(AlgorithmOid.SHA256);
                case 0x8013: return new Oid(AlgorithmOid.SHA384);
                case 0x8014: return new Oid(AlgorithmOid.SHA512);
                default: return null;
            }
        }
        static Int32 getSigAlgIdFromOid(Oid oid) {
            switch (oid.Value) {
                case AlgorithmOid.MD2: return 0x8001;
                case AlgorithmOid.MD5: return 0x8003;
                case AlgorithmOid.SHA1: return 0x8004;
                case AlgorithmOid.SHA256: return 0x8012;
                case AlgorithmOid.SHA384: return 0x8013;
                case AlgorithmOid.SHA512: return 0x8014;
                default: return 0;
            }
        }
        static Oid getEncOidFromAlgId(Int32 algId) {
            switch (algId) {
                case 0x8001: return new Oid(AlgorithmOid.MD2);
                case 0x8003: return new Oid(AlgorithmOid.MD5);
                case 0x8004: return new Oid(AlgorithmOid.SHA1);
                case 0x8012: return new Oid(AlgorithmOid.SHA256);
                case 0x8013: return new Oid(AlgorithmOid.SHA384);
                case 0x8014: return new Oid(AlgorithmOid.SHA512);
                default: return null;
            }
        }
        static Int32 getEncAlgIdFromOid(Oid oid) {
            switch (oid.Value) {
                case AlgorithmOid.DES: return 0x8001;
                case AlgorithmOid.TrippleDES: return 0x8003;
                case AlgorithmOid.AES128: return 0x8004;
                case AlgorithmOid.AES192: return 0x8012;
                case AlgorithmOid.AES256: return 0x8013;
                default: return 0;
            }
        }

        static Boolean validateHashAlgorithm(String value) {
            return new List<String> {
                                        AlgorithmOid.MD2,
                                        AlgorithmOid.MD5,
                                        AlgorithmOid.SHA1,
                                        AlgorithmOid.SHA256,
                                        AlgorithmOid.SHA384,
                                        AlgorithmOid.SHA512
                                    }.Contains(value);
        }
        static Boolean validateEncAlgorithm(String value) {
            return new List<String> {
                                        AlgorithmOid.DES,
                                        AlgorithmOid.TrippleDES,
                                        AlgorithmOid.AES128,
                                        AlgorithmOid.AES192,
                                        AlgorithmOid.AES256
                                    }.Contains(value);
        }
    }
}