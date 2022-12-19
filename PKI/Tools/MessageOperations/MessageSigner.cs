using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using PKI.Exceptions;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Utils.CLRExtensions;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Tools.MessageOperations {
    /// <summary>
    /// Represents the utility which can be used to sign arbitrary data or verify existing signatures by using
    /// asymmetric encryption.
    /// </summary>
    /// <remarks>
    /// This class implements <see cref="IDisposable"/> interface. It is recommended to wrap this class in
    /// <i>using</i> statement to automatically release unmanaged resources during signing procedure.
    /// </remarks>
    public class MessageSigner : IDisposable {
        const String MSFT_KSP_NAME = "Microsoft Software Key Storage Provider";
        Boolean disposed, isCng, nullSigned;
        SafeNCryptKeyHandle phPrivKey = new();
        SafeNCryptKeyHandle phPubKey = new();
        KeyType keyType;
        AsymmetricAlgorithm legacyKey;
        Oid2 hashAlgorithm;
        readonly IKeyStorageInfo _keyInfo;

        MessageSigner() { }
        MessageSigner(Oid2 hashAlg, PublicKey pubKey) {
            PublicKeyAlgorithm = pubKey.Oid;
            acquirePublicKey(pubKey);
            initializeHashAlgorithm(hashAlg);
        }
        internal MessageSigner(X509PrivateKeyBuilder keyBuilder, Oid2 hashAlgorithm)
            : this(hashAlgorithm, keyBuilder.GetPublicKey()) {
            _keyInfo = keyBuilder;
        }

        /// <summary>
        /// Initializes a new instance of the <strong>MessageSigner</strong> class from signer certificate and
        /// default hash algorithm. Default hash algorithm is SHA256.
        /// </summary>
        /// <param name="signer"></param>
        /// <exception cref="ArgumentException">
        ///     <strong>hashAlgorithm</strong> parameter contains invalid hash algorithm identifier.
        /// </exception>
        /// <exception cref="UninitializedObjectException">Signer certificate is not initialized.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>signer</strong> parameter is null.
        /// </exception>
        public MessageSigner(X509Certificate2 signer)
            : this(signer, new Oid2(AlgorithmOid.SHA256, OidGroupEnum.HashAlgorithm, false)) {

        }
        /// <summary>
        /// Initializes a new instance of the <strong>MessageSigner</strong> class from signer certificate and
        /// client-provided hash algorithm.
        /// </summary>
        /// <param name="signer">Signer certificate with associated private key.</param>
        /// <param name="hashAlgorithm">
        /// Hash algorithm that is used to calculate the hash during signing or signature verification
        /// processes.
        /// </param>
        /// <exception cref="ArgumentException">
        ///     <strong>hashAlgorithm</strong> parameter contains invalid hash algorithm identifier.
        /// </exception>
        /// <exception cref="UninitializedObjectException">Signer certificate is not initialized.</exception>
        /// <exception cref="ArgumentNullException">
        /// <strong>signer</strong> and/or <strong>hashAlgorithm</strong> parameter is null.
        /// </exception>
        /// <remarks>
        /// Currently the following hash algorithms are supported:
        /// <list type="bullet">
        ///     <item>MD5</item>
        ///     <item>SHA1</item>
        ///     <item>SHA256</item>
        ///     <item>SHA384</item>
        ///     <item>SHA512</item>
        /// </list>
        /// Hash algorithm is ignored for DSA keys and is automatically set to 'SHA1'.
        /// </remarks>
        public MessageSigner(X509Certificate2 signer, Oid2 hashAlgorithm) : this(hashAlgorithm, signer.PublicKey) {
            if (signer == null) {
                throw new ArgumentNullException(nameof(signer));
            }
            if (hashAlgorithm == null) {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }
            if (IntPtr.Zero.Equals(signer.Handle)) {
                throw new UninitializedObjectException();
            }

            SignerCertificate = signer;
        }

        /// <summary>
        /// Gets the certificate associated with the current instance of <strong>MessageSigner</strong>.
        /// </summary>
        public X509Certificate2 SignerCertificate { get; private set; }
        /// <summary>
        /// Gets public key algorithm.
        /// </summary>
        public Oid PublicKeyAlgorithm { get; }
        /// <summary>
        /// Gets or sets the hashing algorithm that is used to calculate the hash during signing or signature verification
        /// processes.
        /// </summary>
        public Oid2 HashingAlgorithm {
            get => hashAlgorithm;
            set {
                if (value == null || value.OidGroup != OidGroupEnum.HashAlgorithm && value.OidGroup != OidGroupEnum.SignatureAlgorithm) {
                    return;
                }
                initializeHashAlgorithm(value);
            }
        }
        /// <summary>
        /// Gets resulting signature algorithm identifier.
        /// </summary>
        public Oid SignatureAlgorithm { get; private set; }
        /// <summary>
        /// Gets or sets signature padding scheme for RSA signature creation and validation.
        /// Default is <strong>PKCS1</strong>.
        /// </summary>
        public SignaturePadding PaddingScheme { get; set; } = SignaturePadding.PKCS1;
        /// <summary>
        /// Gets or sets the size, in bytes, of the random salt to use for the PSS padding.
        /// Default value matches the hash output length: 16 bytes for MD5, 20 bytes for SHA1, 32 bytes for
        /// SHA256, 48 bytes for SHA384 and 64 bytes for SHA512 hashing algorithm.
        /// </summary>
        public Int32 PssSaltByteCount { get; set; }

        Byte[] calculateHash(Byte[] message) {
            HashAlgorithm hasher = HashAlgorithm.Create(HashingAlgorithm.FriendlyName);
            if (hasher == null) {
                throw new ArgumentException("Invalid hashing algorithm is specified.");
            }
            using (hasher) {
                return hasher.ComputeHash(message);
            }
        }
        void initializeHashAlgorithm(Oid2 hashAlg) {
            if (hashAlg.OidGroup == OidGroupEnum.SignatureAlgorithm) {
                mapSignatureAlgorithmToHashAlgorithm(hashAlg.Value, null);
            } else {
                hashAlgorithm = hashAlg;
            }
            switch (PublicKeyAlgorithm.Value) {
                case AlgorithmOid.RSA:
                    switch (hashAlgorithm.Value) {
                        case AlgorithmOid.MD5: // md5
                            PssSaltByteCount = 16;
                            break;
                        case AlgorithmOid.SHA1: // sha1
                            PssSaltByteCount = 20;
                            break;
                        case AlgorithmOid.SHA256: // sha256
                            PssSaltByteCount = 32;
                            break;
                        case AlgorithmOid.SHA384: // sha384
                            PssSaltByteCount = 48;
                            break;
                        case AlgorithmOid.SHA512: // sha512
                            PssSaltByteCount = 64;
                            break;
                    }
                    break;
                case AlgorithmOid.DSA:
                    // force SHA1 for DSA keys
                    hashAlgorithm = new Oid2(AlgorithmOid.SHA1, false);
                    break;
            }
        }
        void getSignatureAlgorithm() {
            switch (keyType) {
                case KeyType.EcDsa:
                    SignatureAlgorithm = new Oid($"{HashingAlgorithm.FriendlyName}ECDSA"); // ECDSA
                    break;
                case KeyType.Rsa:
                    SignatureAlgorithm = PaddingScheme == SignaturePadding.PSS
                        ? new Oid(AlgorithmOid.RSA_PSS)                              // RSASSA-PSS
                        : new Oid($"{HashingAlgorithm.FriendlyName}RSA"); // RSA
                    break;
                case KeyType.Dsa:
                    // DSA doesn't support PSS padding and hashing algorithm other than SHA1
                    SignatureAlgorithm = new Oid(AlgorithmOid.SHA1_DSA); // sha1DSA
                    break;
            }
        }
        void mapSignatureAlgorithmToHashAlgorithm(String signatureOid, Asn1Reader asn) {
            switch (signatureOid) {
                // md5
                case AlgorithmOid.MD5:
                    nullSigned = true;
                    hashAlgorithm = new Oid2(signatureOid, false);
                    break;
                case AlgorithmOid.MD5_RSA:
                    hashAlgorithm = new Oid2(AlgorithmOid.MD5, false);
                    break;
                // sha1
                case AlgorithmOid.SHA1:
                    nullSigned = true;
                    hashAlgorithm = new Oid2(signatureOid, false);
                    break;
                case AlgorithmOid.SHA1_ECDSA:
                case AlgorithmOid.SHA1_RSA:
                case AlgorithmOid.SHA1_DSA:
                    hashAlgorithm = new Oid2(AlgorithmOid.SHA1, false);
                    break;
                // sha256
                case AlgorithmOid.SHA256:
                    nullSigned = true;
                    hashAlgorithm = new Oid2(signatureOid, false);
                    break;
                case AlgorithmOid.SHA256_ECDSA:
                case AlgorithmOid.SHA256_RSA:
                    hashAlgorithm = new Oid2(AlgorithmOid.SHA256, false);
                    break;
                // sha384
                case AlgorithmOid.SHA384:
                    nullSigned = true;
                    hashAlgorithm = new Oid2(signatureOid, false);
                    break;
                case AlgorithmOid.SHA384_ECDSA:
                case AlgorithmOid.SHA384_RSA:
                    hashAlgorithm = new Oid2(AlgorithmOid.SHA384, false);
                    break;
                // sha512
                case AlgorithmOid.SHA512:
                    nullSigned = true;
                    hashAlgorithm = new Oid2(signatureOid, false);
                    break;
                case AlgorithmOid.SHA512_ECDSA:
                case AlgorithmOid.SHA512_RSA:
                    hashAlgorithm = new Oid2(AlgorithmOid.SHA512, false);
                    break;
                case AlgorithmOid.ECDSA_SPECIFIED:
                    decodeEcdsaSpecified(asn);
                    break;
                case AlgorithmOid.RSA_PSS:
                    decodeRsaPss(asn);
                    break;
                default:
                    throw new ArgumentException("Invalid signature algorithm");
            }
        }
        void getConfiguration(Byte[] algIdBlob) {
            var asn = new Asn1Reader(algIdBlob);
            asn.MoveNext();
            var oid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
            asn.MoveNext();
            mapSignatureAlgorithmToHashAlgorithm(oid.Value, asn);
        }
        void decodeEcdsaSpecified(Asn1Reader asn) {
            hashAlgorithm = new Oid2(new AlgorithmIdentifier(asn.GetTagRawData()).AlgorithmId, false);
        }
        void decodeRsaPss(Asn1Reader asn) {
            PaddingScheme = SignaturePadding.PSS;
            asn.MoveNext();
            hashAlgorithm = asn.Tag == 0xa0
                ? new Oid2(new AlgorithmIdentifier(asn.GetPayload()).AlgorithmId, false)
                : new Oid2(AlgorithmOid.SHA1, false);
            // feed asn reader to salt identifier
            while (asn.MoveNextSibling() && asn.Tag != 0xa2) { }
            PssSaltByteCount = asn.Tag == 0xa2
                ? (Int32)Asn1Utils.DecodeInteger(asn.GetPayload())
                : 20;
        }

        #region Key pair operations
        Boolean checkPrivateKeyIsLoaded() {
            if (isCng) {
                return !phPrivKey.IsInvalid;
            }

            return legacyKey != null;
        }
        Boolean checkPublicKeyIsLoaded() {
            return !phPubKey.IsInvalid;
        }

        void acquirePrivateKey() {
            if (disposed) {
                throw new ObjectDisposedException("PrivateKey");
            }
            // the key is already acquired, so skip key retrieval
            if (checkPrivateKeyIsLoaded()) { return; }

            if (_keyInfo != null) {
                acquirePrivateKeyFromKeyBuilder();
            } else if (SignerCertificate != null) {
                acquirePrivateKeyFromCert();
            } else {
                throw new CryptographicException("Private key source cannot found.");
            }
        }
        void acquirePrivateKeyFromKeyBuilder() {
            Int32 hresult = NCrypt.NCryptOpenStorageProvider(out SafeNCryptProviderHandle phProv, _keyInfo.ProviderName, 0);
            if (hresult != 0) {
                openLegacyPrivateKey();
                return;
            }
            UInt32 dwFlags = 0;
            if (_keyInfo.MachineContext) {
                dwFlags = nCrypt2.NCRYPT_MACHINE_KEY_FLAG;
            }
            hresult = NCrypt.NCryptOpenKey(phProv, out phPrivKey, _keyInfo.KeyContainerName, (UInt32)_keyInfo.KeySpec, dwFlags);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }
            isCng = true;
        }
        void openLegacyPrivateKey() {
            var cspParams = new CspParameters(_keyInfo.ProviderType, _keyInfo.ProviderName, _keyInfo.KeyContainerName);
            switch (_keyInfo.PublicKeyAlgorithm.Value) {
                case AlgorithmOid.RSA:
                    legacyKey = new RSACryptoServiceProvider(cspParams);
                    if (((RSACryptoServiceProvider)legacyKey).PublicOnly) {
                        throw new CryptographicException("Private key cannot be found.");
                    }
                    break;
                case AlgorithmOid.DSA:
                    legacyKey = new DSACryptoServiceProvider(cspParams);
                    if (((DSACryptoServiceProvider)legacyKey).PublicOnly) {
                        throw new CryptographicException("Private key was not found");
                    }
                    break;
                default:
                    throw new CryptographicException("Key algorithm is not valid.");
            }
        }
        void acquirePrivateKeyFromCert() {
            // the key is not acquired, so attempt to get it
            if (!Crypt32.CryptAcquireCertificatePrivateKey(
                SignerCertificate.Handle,
                Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                IntPtr.Zero,
                out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
                out UInt32 pdwKeySpec,
                out Boolean _)) {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            if (pdwKeySpec == UInt32.MaxValue) {
                phPrivKey = phCryptProvOrNCryptKey;
                isCng = true;
            } else {
                // translate legacy CSP key to CNG key handle
                getCngHandleFromLegacy(phCryptProvOrNCryptKey);
            }
        }
        void acquirePublicKey(PublicKey publicKey) {
            // do not load public key again if it is already loaded
            if (checkPublicKeyIsLoaded()) { return; }
            switch (publicKey.Oid.Value) {
                case AlgorithmOid.ECC:
                    keyType = KeyType.EcDsa;
                    break;
                case AlgorithmOid.RSA:
                    keyType = KeyType.Rsa;
                    break;
                case AlgorithmOid.DSA:
                    keyType = KeyType.Dsa;
                    break;
                default:
                    throw new NotSupportedException("Public key algorithm is not supported");
            }

            // regardless of public key algorithm and provider, load public keys to CNG provider for unification
            // and wider signature formats and padding support.
            Int32 hresult = NCrypt.NCryptOpenStorageProvider(out SafeNCryptProviderHandle phProvider, MSFT_KSP_NAME, 0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            Byte[] blob = publicKey.GetCryptBlob();
            hresult = NCrypt.NCryptImportKey(phProvider, IntPtr.Zero, "PUBLICBLOB", IntPtr.Zero, out phPubKey, blob,
                blob.Length, 0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }
        }
        void getCngHandleFromLegacy(SafeHandle phCryptProvOrNCryptKey) {
            // attempt to translate legacy HCRYPTPROV handle to CNG key handle
            Int32 hresult = NCrypt.NCryptTranslateHandle(
                IntPtr.Zero,
                out SafeNCryptKeyHandle cngKey,
                phCryptProvOrNCryptKey,
                IntPtr.Zero,
                (UInt32)X509KeySpecFlags.AT_NONE,
                0);
            // release legacy HCRYPTPROV handle
            AdvAPI.CryptReleaseContext(phCryptProvOrNCryptKey.DangerousGetHandle(), 0);
            if (hresult == 0) {
                // if key is successfully translated, assign new CNG key handle to phPrivKey
                phPrivKey = cngKey;
                isCng = true;
            } else {
                // if key translation failed, then switch to legacy RSA/DSACryptoServiceProvider
                isCng = false;
                legacyKey = SignerCertificate.PrivateKey;
            }
        }
        #endregion

        #region Generics
        delegate Int32 NCryptSignHash<T>(
            SafeNCryptKeyHandle hKey,
            ref T pvPaddingInfo,
            Byte[] pbHashValue,
            Int32 cbHashValue,
            Byte[] pbSignature,
            Int32 cbSignature,
            out Int32 pcbResult,
            SignaturePadding dwFlags) where T : struct;

        delegate Int32 NCryptVerifySignature<T>(
            SafeNCryptKeyHandle hKey,
            ref T pvPaddingInfo,
            Byte[] pbHashValue,
            Int32 cbHashValue,
            Byte[] pbSignature,
            Int32 cbSignature,
            SignaturePadding dwFlags) where T : struct;

        Byte[] signHashCngGeneric<T>(Byte[] hash, T padding, NCryptSignHash<T> signer)
            where T : struct {
            Int32 hresult = signer(
                phPrivKey,
                ref padding,
                hash,
                hash.Length,
                null,
                0,
                out Int32 pcbResult,
                PaddingScheme);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            Byte[] pbSignature = new Byte[pcbResult];
            hresult = signer(
                phPrivKey,
                ref padding,
                hash,
                hash.Length,
                pbSignature,
                pbSignature.Length,
                out _,
                PaddingScheme);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            return pbSignature;
        }
        Boolean verifyHashGeneric<T>(Byte[] hash, Byte[] signature, T padding, NCryptVerifySignature<T> signer)
            where T : struct {
            Int32 hresult = signer(
                phPubKey,
                ref padding,
                hash,
                hash.Length,
                signature,
                signature.Length,
                PaddingScheme);
            return hresult == 0;
        }
        #endregion

        #region signature creation
        // base methods. They decide which routine to call depending on configuration state
        Byte[] signHashEcDsa(Byte[] hash) {
            return signHashEcDsaCng(hash);
        }
        Byte[] signHashDsa(Byte[] hash) {
            return isCng
                ? signHashDsaCng(hash)
                : signHashDsaLegacy(hash);
        }
        Byte[] signHashRsa(Byte[] hash) {
            return isCng
                ? (PaddingScheme == SignaturePadding.PSS
                    ? signHashRsaCngPss(hash)
                    : signHashRsaCngPkcs1(hash))
                : signHashRsaLegacy(hash);
        }

        // signing with CNG keys
        Byte[] signHashEcDsaCng(Byte[] hash) {
            Int32 hresult = NCrypt.NCryptSignHash(
                phPrivKey,
                IntPtr.Zero,
                hash,
                hash.Length,
                null,
                0,
                out Int32 pcbResult,
                0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            Byte[] pbSignature = new Byte[pcbResult];
            hresult = NCrypt.NCryptSignHash(
                phPrivKey,
                IntPtr.Zero,
                hash,
                hash.Length,
                pbSignature,
                pbSignature.Length,
                out pcbResult,
                0);
            if (hresult != 0) {
                throw new CryptographicException(hresult);
            }

            return pbSignature;
        }
        Byte[] signHashRsaCngPkcs1(Byte[] hash) {
            var pad = new nCrypt2.BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper()
            };
            return signHashCngGeneric(hash, pad, NCrypt.NCryptSignHash);
        }
        Byte[] signHashRsaCngPss(Byte[] hash) {
            var pad = new nCrypt2.BCRYPT_PSS_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper(),
                cbSalt = PssSaltByteCount
            };
            return signHashCngGeneric(hash, pad, NCrypt.NCryptSignHash);
        }
        Byte[] signHashDsaCng(Byte[] hash) {
            return signHashEcDsa(hash);
        }

        // specific fallback methods when legacy key cannot be translated to CNG key.
        // Hardware-based legacy CSPs fall to this category.
        Byte[] signHashRsaLegacy(Byte[] hash) {
            // overwrite padding to PKCS1, legacy CSP doesn't support PSS.
            PaddingScheme = SignaturePadding.PKCS1;
            return ((RSACryptoServiceProvider)legacyKey).SignHash(hash, HashingAlgorithm.Value);
        }
        Byte[] signHashDsaLegacy(Byte[] hash) {
            return ((DSACryptoServiceProvider)legacyKey).SignHash(hash, "sha1");
        }
        #endregion

        #region signature validation
        Boolean verifyNullSigned(Byte[] hash, Byte[] signature) {
            if (hash.Length != signature.Length) { return false; }
            // performs exact binary comparison
            return !hash.Where((t, index) => t != signature[index]).Any();
        }
        Boolean verifyHashEcDsa(Byte[] hash, Byte[] signature) {
            Int32 hresult = NCrypt.NCryptVerifySignature(phPubKey, IntPtr.Zero, hash, hash.Length, signature,
                signature.Length, 0);
            return hresult == 0;
        }
        Boolean verifyHashRsa(Byte[] hash, Byte[] signature) {
            return PaddingScheme == SignaturePadding.PSS
                ? verifyHashRsaPss(hash, signature)
                : verifyHashRsaPkcs1(hash, signature);
        }
        Boolean verifyHashDsa(Byte[] hash, Byte[] signature) {
            return verifyHashEcDsa(hash, signature);
        }

        Boolean verifyHashRsaPkcs1(Byte[] hash, Byte[] signature) {
            var pad = new nCrypt2.BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper()
            };
            return verifyHashGeneric(hash, signature, pad, NCrypt.NCryptVerifySignature);
        }
        Boolean verifyHashRsaPss(Byte[] hash, Byte[] signature) {
            var pad = new nCrypt2.BCRYPT_PSS_PADDING_INFO {
                pszAlgId = HashingAlgorithm.FriendlyName.ToUpper(),
                cbSalt = PssSaltByteCount
            };
            return verifyHashGeneric(hash, signature, pad, NCrypt.NCryptVerifySignature);
        }
        #endregion

        /// <summary>
        /// Signs the data with signer's private key and specified hash algorithm.
        /// </summary>
        /// <param name="message">Raw message to sign.</param>
        /// <exception cref="ArgumentNullException"><strong>message</strong> parameter is null.</exception>
        /// <returns>Raw signature.</returns>
        /// <remarks>For DSA private key only SHA1 hash is used.</remarks>
        public Byte[] SignData(Byte[] message) {
            if (message == null) { throw new ArgumentNullException(nameof(message)); }
            return SignHash(calculateHash(message));
        }
        /// <summary>
        /// Signs the hash with signer's private key.
        /// </summary>
        /// <param name="hash">Hash to sign.</param>
        /// <exception cref="ArgumentNullException"><strong>hash</strong> parameter is null.</exception>
        /// <returns>Raw signature.</returns>
        public Byte[] SignHash(Byte[] hash) {
            if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
            acquirePrivateKey();
            Byte[] signature;
            switch (keyType) {
                case KeyType.EcDsa:
                    signature = signHashEcDsa(hash);
                    break;
                case KeyType.Rsa:
                    signature = signHashRsa(hash);
                    break;
                case KeyType.Dsa:
                    signature = signHashDsa(hash);
                    break;
                default:
                    throw new InvalidOperationException(new Win32Exception(Error.InvalidParameterException).Message);
            }
            getSignatureAlgorithm();
            return signature;
        }

        /// <summary>
        /// Verifies that the specified signature matches the specified hash.
        /// </summary>
        /// <param name="message">The data that was signed.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>message</strong> or <strong>signature</strong> parameter is null.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
        /// </returns>
        public Boolean VerifyData(Byte[] message, Byte[] signature) {
            if (message == null) { throw new ArgumentNullException(nameof(message)); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature)); }

            return VerifyHash(calculateHash(message), signature);
        }
        /// <summary>
        /// Verifies that the specified signature matches the specified hash.
        /// </summary>
        /// <param name="hash">The hash value of the signed data.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>hash</strong> or <strong>signature</strong> parameter is null.
        /// </exception>
        /// <returns>
        /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
        /// </returns>
        public Boolean VerifyHash(Byte[] hash, Byte[] signature) {
            if (hash == null) { throw new ArgumentNullException(nameof(hash)); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature)); }

            if (nullSigned) {
                return verifyNullSigned(hash, signature);
            }
            switch (keyType) {
                case KeyType.EcDsa:
                    return verifyHashEcDsa(hash, signature);
                case KeyType.Rsa:
                    return verifyHashRsa(hash, signature);
                case KeyType.Dsa:
                    return verifyHashDsa(hash, signature);
                default:
                    throw new NotSupportedException("Public key algorithm is not supported");
            }
        }
        /// <summary>
        /// Verifies signature of a signed blob by using specified public key.
        /// </summary>
        /// <param name="blob"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        /// <remarks>
        /// This method is suitable to validate certificate signing requests (CSR) or other data
        /// when signing key pair exist outside of X.509 certificate object.
        /// </remarks>
        public static Boolean VerifyData(SignedContentBlob blob, PublicKey publicKey) {
            if (blob == null) { throw new ArgumentNullException(nameof(blob)); }
            if (publicKey == null) { throw new ArgumentNullException(nameof(publicKey)); }

            if (blob.BlobType != ContentBlobType.SignedBlob) {
                throw new InvalidOperationException("The blob is not signed.");
            }

            using var signerInfo = new MessageSigner();
            signerInfo.acquirePublicKey(publicKey);
            signerInfo.getConfiguration(blob.SignatureAlgorithm.RawData);
            return signerInfo.VerifyData(blob.ToBeSignedData, blob.GetRawSignature());
        }

        /// <summary>
        /// Gets ASN-encoded algorithm identifier based on current configuration.
        /// </summary>
        /// <param name="alternate">
        /// Specifies whether alternate signature format is used. This parameter has meaning only for
        /// ECDSA keys. Otherwise, the parameter is ignored. Default value is <strong>false</strong>.
        /// </param>
        /// <returns>ASN-encoded algorithm identifier.</returns>
        public AlgorithmIdentifier GetAlgorithmIdentifier(Boolean alternate = false) {
            if (SignatureAlgorithm == null) {
                getSignatureAlgorithm();
            }
            Oid algId = SignatureAlgorithm;
            List<Byte> parameters = new List<Byte>();
            switch (PublicKeyAlgorithm.Value) {
                case AlgorithmOid.ECC: // ECDSA
                    if (alternate) {
                        // specifiedECDSA
                        algId = new Oid(AlgorithmOid.ECDSA_SPECIFIED); // only here we override algorithm OID
                        parameters
                            .AddRange(
                                new AlgorithmIdentifier(HashingAlgorithm.ToOid(), Asn1Utils.EncodeNull()).RawData
                            );
                    }
                    break;
                case AlgorithmOid.RSA: // RSA
                    // only RSA supports parameters. For PKCS1 padding: NULL, for PSS padding: 
                    // RSASSA-PSS-params ::= SEQUENCE {
                    //     hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
                    //     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
                    //     saltLength         [2] INTEGER          DEFAULT 20,
                    //     trailerField       [3] TrailerField     DEFAULT trailerFieldBC
                    // }
                    if (PaddingScheme == SignaturePadding.PSS) {
                        Byte[] hash = new AlgorithmIdentifier(HashingAlgorithm.ToOid(), null).RawData;
                        parameters.AddRange(Asn1Utils.Encode(hash, 0xa0));
                        // mask generation function: mgf1
                        Byte[] mgf = new AlgorithmIdentifier(new Oid("1.2.840.113549.1.1.8"), hash).RawData;
                        parameters.AddRange(Asn1Utils.Encode(mgf, 0xa1));
                        // salt
                        parameters.AddRange(Asn1Utils.Encode(new Asn1Integer(20).RawData, 0xa2));
                        // general PSS parameters encode
                        parameters = new List<Byte>(Asn1Utils.Encode(parameters.ToArray(), 48));
                    } else {
                        parameters.AddRange(Asn1Utils.EncodeNull());
                    }
                    break;
            }
            return new AlgorithmIdentifier(algId, parameters.ToArray());
        }

        #region IDisposable implementation
        void releaseUnmanagedResources() {
            // dispose public key handle
            phPubKey.Dispose();
            if (isCng) {
                // dispose CNG private key handle
                phPrivKey.Dispose();
            } else {
                // dispose legacy private CSP key
                legacyKey?.Dispose();
                legacyKey = null;
            }
            //TODO: Crypt32.CertFreeCertificateContext(SignerCertificate.Handle);
            SignerCertificate = null;
            disposed = true;
        }
        /// <inheritdoc />
        public void Dispose() {
            releaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }
        /// <inheritdoc />
        ~MessageSigner() {
            releaseUnmanagedResources();
        }
        #endregion

        enum KeyType {
            EcDsa,
            Rsa,
            Dsa
        }
    }
}
