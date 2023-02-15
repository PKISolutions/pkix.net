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
        const String S_NODE = KEY_CSP;
        const String E_NODE = KEY_ENCRYPTIONCSP;

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
        /// <remarks>
        ///     If new provider is legacy CSP, <see cref="EncryptionPublicKeyAlgorithm"/> is automatically set to <strong>RSA</strong>.
        /// </remarks>
        public CspProviderInfo SigningProvider {
            get => sigProv;
            set {
                if (value == null || sigProv.Name.Equals(value.Name, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }

                sigProv = value;
                if (sigProv.IsLegacy) {
                    sigPubKeyAlg = new Oid(AlgorithmOid.RSA);
                }
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the public key algorithm (such as RSA, DSA or ECC) that is used to generate CA Exchange encryption certificate.
        /// Use <strong>ECDH_*</strong> for ECC-based public key. 
        /// </summary>
        /// <remarks>
        ///     Setter is ignored if provider specified in <see cref="EncryptionProvider"/> property is legacy provider.
        /// <para>
        /// When setting new algorithm name, <see cref="EncryptionPublicKeyLength"/> property is updated as follows:
        /// <list type="bullet">
        ///     <item>For RSA, key length is set to 2048</item>
        ///     <item>For DSA, key length is set to 1024</item>
        ///     <item>For ECC named curve, key length is set to a value corresponding to that curve</item>
        /// </list>
        /// </para>
        /// </remarks>
        public Oid EncryptionPublicKeyAlgorithm {
            get => encPubKeyAlg;
            set {
                if (sigProv.IsLegacy && encPubKeyAlg != null && value.Value == encPubKeyAlg.Value) {
                    return;
                }

                encPubKeyAlg = value;
                switch (encPubKeyAlg.Value) {
                    case AlgorithmOid.SecP160K1:
                    case AlgorithmOid.SecP160R1:
                    case AlgorithmOid.SecP160R2:
                        encPubKeyLength = 160;
                        break;
                    case AlgorithmOid.SecP192K1:
                        encPubKeyLength = 192;
                        break;
                    case AlgorithmOid.SecP224K1:
                    case AlgorithmOid.NistP224:
                        encPubKeyLength = 224;
                        break;
                    case AlgorithmOid.SecP256K1:
                    case AlgorithmOid.ECDSA_P256:
                        encPubKeyLength = 256;
                        break;
                    case AlgorithmOid.ECDSA_P384:
                        encPubKeyLength = 384;
                        break;
                    case AlgorithmOid.ECDSA_P521:
                        encPubKeyLength = 521;
                        break;
                    case AlgorithmOid.RSA:
                        encPubKeyLength = 2048;
                        break;
                    case AlgorithmOid.DSA:
                        encPubKeyLength = 1024;
                        break;
                }
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets or sets the CA Exchange public key length.
        /// </summary>
        /// <remarks>Setter is applicable only when CA uses RSA public key algorithm and setter value is ignored if CA uses ECC public key.</remarks>
        public Int32 EncryptionPublicKeyLength {
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
        /// <remarks>Setter of this property automatically updates <see cref="EncryptionKeyLength"/> property to corresponding value.</remarks>
        public Oid EncryptionAlgorithm {
            get => encSymmetricAlg;
            set {
                if (encSymmetricAlg != null && value.Value == encSymmetricAlg.Value || !validateEncAlgorithm(value.Value)) {
                    return;
                }
                encSymmetricAlg = value;
                switch (encSymmetricAlg.Value) {
                    case AlgorithmOid.DES:
                        EncryptionKeyLength = 56;
                        break;
                    case AlgorithmOid.TrippleDES:
                        EncryptionKeyLength = 168;
                        break;
                    case AlgorithmOid.AES128:
                        EncryptionKeyLength = 128;
                        break;
                    case AlgorithmOid.AES192:
                        EncryptionKeyLength = 192;
                        break;
                    case AlgorithmOid.AES256:
                        EncryptionKeyLength = 256;
                        break;
                }
                IsModified = true;
            }
        }
        /// <summary>
        /// Gets the length of symmetric encryption key. This property is automatically updated when setting <see cref="EncryptionAlgorithm"/> member.
        /// </summary>
        public Int32 EncryptionKeyLength { get; private set; }
        /// <summary>
        /// Gets or sets the provider name that is used to store CA Exchange keys.
        /// </summary>
        /// <remarks>
        /// If new provider is legacy the following configuration is changed:
        /// <list type="bullet">
        ///     <item><see cref="EncryptionAlgorithm"/> is set to <strong>3DES</strong></item>
        ///     <item><see cref="EncryptionKeyLength"/> is set to <strong>168</strong></item>
        ///     <item><see cref="EncryptionPublicKeyAlgorithm"/> is set to <strong>RSA</strong></item>
        ///     <item><see cref="EncryptionPublicKeyLength"/> is set to <strong>2048</strong></item>
        /// </list>
        /// </remarks>
        public CspProviderInfo EncryptionProvider {
            get => encProv;
            set {
                if (value == null || encProv.Name.Equals(value.Name, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }

                encProv = value;
                if (encProv.IsLegacy) {
                    EncryptionAlgorithm = new Oid(AlgorithmOid.TrippleDES);
                    EncryptionPublicKeyAlgorithm = new Oid(AlgorithmOid.RSA);
                }
                IsModified = true;
            }
        }

        protected override void OnCommit() {
            if (!IsModified) {
                return;
            }

            // CSP node
            ConfigEntries.Add(new RegConfigEntry(CSP_PROVIDER, S_NODE, sigProv.Name));
            ConfigEntries.Add(new RegConfigEntry(CSP_PROVIDERTYPE, S_NODE, sigProv.IsLegacy));
            ConfigEntries.Add(new RegConfigEntry(CSP_ALTERNATESIGNATUREALGORITHM, S_NODE, !encProv.IsLegacy && alternateSignatureAlgorithm));
            if (sigProv.IsLegacy) {
                ConfigEntries.Add(new RegConfigEntry(CSP_HASHALGORITHM, S_NODE, getSigAlgIdFromOid(hashingAlgorithm)));
            } else {
                ConfigEntries.Add(new RegConfigEntry(CSP_HASHALGORITHM, S_NODE, -1));
                ConfigEntries.Add(new RegConfigEntry(CSP_CNGHASHALGORITHM, S_NODE, hashingAlgorithm.FriendlyName.ToUpper()));
                ConfigEntries.Add(new RegConfigEntry(CSP_CNGPUBLICKEYALGORITHM, S_NODE, sigPubKeyAlg.FriendlyName.ToUpper()));
            }

            // Encryption CSP node
            ConfigEntries.Add(new RegConfigEntry(CSP_PROVIDER, E_NODE, encProv.Name));
            ConfigEntries.Add(new RegConfigEntry(CSP_PROVIDERTYPE, E_NODE, encProv.IsLegacy));
            ConfigEntries.Add(new RegConfigEntry(CSP_KEYSIZE, E_NODE, encPubKeyLength));
            if (encProv.IsLegacy) {
                ConfigEntries.Add(new RegConfigEntry(CSP_ENCRYPTIONALGORITHM, E_NODE, 0x6603));
                ConfigEntries.Add(new RegConfigEntry(CSP_SYMMETRICKEYSIZE, E_NODE, 168));
            } else {
                ConfigEntries.Add(new RegConfigEntry(CSP_ENCRYPTIONALGORITHM, E_NODE, -1));
                ConfigEntries.Add(new RegConfigEntry(CSP_CNGPUBLICKEYALGORITHM, E_NODE, encPubKeyAlg.FriendlyName.ToUpper()));
                Tuple<String, Int32> tuple = getSymmetricAlgorithmToWrite();
                ConfigEntries.Add(new RegConfigEntry(CSP_CNGENCRYPTIONALGORITHM, E_NODE, tuple.Item1));
                ConfigEntries.Add(new RegConfigEntry(CSP_SYMMETRICKEYSIZE, E_NODE, tuple.Item2));
            }
        }

        void readSigningCrypto() {
            sigProv = CspProviderInfoCollection.GetProviderInfo(ConfigManager.GetStringEntry(CSP_PROVIDER, S_NODE));
            sigPubKeyAlg = sigProv.IsLegacy
                ? new Oid(AlgorithmOid.RSA)
                : new Oid(ConfigManager.GetStringEntry(CSP_CNGPUBLICKEYALGORITHM, S_NODE));
            if (sigProv.IsLegacy) {
                // legacy
                hashingAlgorithm = getSigOidFromAlgId(ConfigManager.GetNumericEntry(CSP_HASHALGORITHM, S_NODE));
            } else {
                // CNG
                hashingAlgorithm = new Oid(ConfigManager.GetStringEntry(CSP_CNGHASHALGORITHM, S_NODE));
                alternateSignatureAlgorithm = ConfigManager.GetBooleanEntry(CSP_ALTERNATESIGNATUREALGORITHM, S_NODE);
            }
        }
        void readEncryptionCrypto() {
            // encryption crypto
            encProv = CspProviderInfoCollection.GetProviderInfo(ConfigManager.GetStringEntry(CSP_PROVIDER, E_NODE));
            EncryptionKeyLength = ConfigManager.GetNumericEntry(CSP_SYMMETRICKEYSIZE, E_NODE);
            if (encProv.IsLegacy) {
                // Win2k3
                encPubKeyAlg = new Oid(AlgorithmOid.RSA);
                encSymmetricAlg = new Oid(AlgorithmOid.TrippleDES);
            } else {
                String symAlgID = ConfigManager.GetStringEntry(CSP_CNGENCRYPTIONALGORITHM, E_NODE);
                getEncAlg(symAlgID, EncryptionKeyLength);
                encPubKeyAlg = new Oid(ConfigManager.GetStringEntry(CSP_CNGPUBLICKEYALGORITHM, E_NODE));
            }
            
            encPubKeyLength = ConfigManager.GetNumericEntry(CSP_KEYSIZE, E_NODE);
        }

        void getEncAlg(String algString, Int32 keyLength) {
            var oid = new Oid(algString ?? String.Empty);
            switch (oid.Value.ToUpper()) {
                case "DES":
                case "3DES":
                    encSymmetricAlg = oid;
                    break;
                case "AES":
                    switch (keyLength) {
                        case 128:
                            encSymmetricAlg = new Oid(AlgorithmOid.AES128);
                            break;
                        case 192:
                            encSymmetricAlg = new Oid(AlgorithmOid.AES192);
                            break;
                        case 256:
                            encSymmetricAlg = new Oid(AlgorithmOid.AES256);
                            break;
                        default:
                            encSymmetricAlg = oid;
                            break;
                    }
                    break;
                default:
                    encSymmetricAlg = oid;
                    break;
            }
        }
        Tuple<String, Int32> getSymmetricAlgorithmToWrite() {
            String algString = encSymmetricAlg.FriendlyName.ToUpper();
            Int32 algLength = EncryptionKeyLength;

            switch (encSymmetricAlg.Value) {
                case AlgorithmOid.DES:
                    algString = encSymmetricAlg.FriendlyName.ToUpper();
                    algLength = 56;
                    break;
                case AlgorithmOid.TrippleDES:
                    algString = encSymmetricAlg.FriendlyName.ToUpper();
                    algLength = 168;
                    break;
                case AlgorithmOid.AES128:
                    algString = "AES";
                    algLength = 128;
                    break;
                case AlgorithmOid.AES192:
                    algString = "AES";
                    algLength = 192;
                    break;
                case AlgorithmOid.AES256:
                    algString = "AES";
                    algLength = 256;
                    break;
            }

            return new Tuple<String, Int32>(algString, algLength);
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