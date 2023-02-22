using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;
public class CryptSigner : ICryptSigner, IDisposable {
    const String DEFAULT_HASH_ALG = AlgorithmOid.SHA256;

    Boolean nullSigned;
    AsymmetricAlgorithm phPubKey;
    AsymmetricAlgorithm phPrivKey;
    Oid hashAlgorithm, sigAlgorithm;
    KeyType keyType;

    CryptSigner() {

    }

    public CryptSigner(AsymmetricKeyPair keyPair, Oid hashingAlgorithm = null) {
        if (keyPair == null) {
            throw new ArgumentNullException(nameof(keyPair));
        }

        hashingAlgorithm ??= new Oid(DEFAULT_HASH_ALG);
        acquirePublicKey(keyPair);
        hashAlgorithm = getHashAlgorithm(hashingAlgorithm);
        if (!keyPair.PublicOnly) {
            phPrivKey = keyPair.GetAsymmetricKey();
        }
    }

    /// <summary>
    /// Initializes a new instance of the <strong>CryptSigner</strong> class from signer certificate and
    /// client-provided hash algorithm.
    /// </summary>
    /// <param name="certificate">Signer certificate with associated private key.</param>
    /// <param name="hashingAlgorithm">
    /// Hash algorithm that is used to calculate the hash during signing or signature verification
    /// processes.
    /// </param>
    /// <exception cref="ArgumentException">
    ///     <strong>hashAlgorithm</strong> parameter contains invalid hash algorithm identifier.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <strong>signer</strong> and/or <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    /// <remarks>
    /// Currently, the following hash algorithms are supported:
    /// <list type="bullet">
    ///     <item>MD5</item>
    ///     <item>SHA1</item>
    ///     <item>SHA256</item>
    ///     <item>SHA384</item>
    ///     <item>SHA512</item>
    /// </list>
    /// Hash algorithm is ignored for DSA keys and is automatically set to 'SHA1'.
    /// </remarks>
    public CryptSigner(X509Certificate2 certificate, Oid hashingAlgorithm) {
        SignerCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        hashingAlgorithm ??= new Oid(DEFAULT_HASH_ALG);
        acquirePublicKey(certificate.PublicKey.GetAsymmetricKeyPair());
        hashAlgorithm = getHashAlgorithm(hashingAlgorithm);
        if (certificate.HasPrivateKey) {
            acquirePrivateKey();
        }
    }

    /// <summary>
    /// Gets the certificate associated with the current instance of <strong>MessageSigner</strong>.
    /// </summary>
    public X509Certificate2 SignerCertificate { get; private set; }
    /// <summary>
    /// Gets public key algorithm.
    /// </summary>
    public Oid PublicKeyAlgorithm { get; private set; }
    /// <summary>
    /// Gets or sets the hashing algorithm that is used to calculate the hash during signing or signature verification
    /// processes.
    /// </summary>
    public Oid HashingAlgorithm {
        get => new(hashAlgorithm);
        set => hashAlgorithm = getHashAlgorithm(value);
    }
    /// <summary>
    /// Gets resulting signature algorithm identifier.
    /// </summary>
    public Oid SignatureAlgorithm => new(sigAlgorithm);
    /// <summary>
    /// Gets or sets signature padding scheme for RSA signature creation and validation.
    /// Default is <strong>PKCS1</strong>.
    /// </summary>
    public RSASignaturePadding PaddingScheme { get; set; } = RSASignaturePadding.Pkcs1;
    /// <summary>
    /// Gets or sets the size, in bytes, of the random salt to use for the PSS padding.
    /// Default value matches the hash output length: 16 bytes for MD5, 20 bytes for SHA1, 32 bytes for
    /// SHA256, 48 bytes for SHA384 and 64 bytes for SHA512 hashing algorithm.
    /// </summary>
    public Int32 PssSaltByteCount { get; set; }

    Oid getHashAlgorithm(Oid hashAlg) {
        Oid oid;
        try {
            oid = Oid.FromOidValue(hashAlg.Value, OidGroup.HashAlgorithm);
        } catch {
            oid = mapSignatureAlgorithmToHashAlgorithm(hashAlg.Value, null);
        }

        switch (keyType) {
            case KeyType.Rsa:
                switch (oid.Value) {
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
            case KeyType.Dsa:
                // force SHA1 for DSA keys
                oid = new Oid(AlgorithmOid.SHA1);
                break;
        }

        return oid;
    }
    Oid mapSignatureAlgorithmToHashAlgorithm(String signatureOid, Asn1Reader asn) {
        switch (signatureOid) {
            // md5
            case AlgorithmOid.MD5:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.MD5_RSA:
                return new Oid(AlgorithmOid.MD5);
            // sha1
            case AlgorithmOid.SHA1:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA1_ECDSA:
            case AlgorithmOid.SHA1_RSA:
            case AlgorithmOid.SHA1_DSA:
                return new Oid(AlgorithmOid.SHA1);
            // sha256
            case AlgorithmOid.SHA256:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA256_ECDSA:
            case AlgorithmOid.SHA256_RSA:
                return new Oid(AlgorithmOid.SHA256);
            // sha384
            case AlgorithmOid.SHA384:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA384_ECDSA:
            case AlgorithmOid.SHA384_RSA:
                return new Oid(AlgorithmOid.SHA384);
            // sha512
            case AlgorithmOid.SHA512:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA512_ECDSA:
            case AlgorithmOid.SHA512_RSA:
                return new Oid(AlgorithmOid.SHA512);
            case AlgorithmOid.ECDSA_SPECIFIED:
                return new Oid(new AlgorithmIdentifier(asn.GetTagRawData()).AlgorithmId);
            case AlgorithmOid.RSA_PSS:
                return decodeRsaPss(asn);
            default:
                throw new ArgumentException("Invalid signature algorithm");
        }


    }
    Oid decodeRsaPss(Asn1Reader asn) {
        PaddingScheme = RSASignaturePadding.Pss;
        asn.MoveNext();
        Oid hAlgId = asn.Tag == 0xa0
            ? new Oid(new AlgorithmIdentifier(asn.GetPayload()).AlgorithmId)
            : new Oid(AlgorithmOid.SHA1);
        // feed asn reader to salt identifier
        while (asn.MoveNextSibling() && asn.Tag != 0xa2) { }
        PssSaltByteCount = asn.Tag == 0xa2
            ? (Int32)new Asn1Integer(asn.GetPayload()).Value
            : 20;
        return hAlgId;
    }
    void getConfiguration(Byte[] algIdBlob) {
        var asn = new Asn1Reader(algIdBlob);
        asn.MoveNext();
        Oid oid = new Asn1ObjectIdentifier(asn).Value;
        asn.MoveNext();
        hashAlgorithm = mapSignatureAlgorithmToHashAlgorithm(oid.Value, asn);
    }

    Byte[] calculateHash(Byte[] message) {
        using var hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName);
        if (hasher == null) {
            throw new ArgumentException("Invalid hashing algorithm is specified.");
        }

        return hasher.ComputeHash(message);
    }
    void acquirePublicKey(AsymmetricKeyPair keyPair) {
        // do not load public key again if it is already loaded
        if (phPubKey != null) {
            return;
        }

        switch (keyPair.Oid.Value) {
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
                throw new NotSupportedException("Public key algorithm is not supported.");
        }
        PublicKeyAlgorithm = keyPair.Oid;
        phPubKey = keyPair.GetAsymmetricKey();
    }
    void acquirePrivateKey() {
        // do not load public key again if it is already loaded
        if (phPrivKey != null) {
            return;
        }
        if (SignerCertificate != null) {
            Func<AsymmetricAlgorithm> action = null;
            switch (SignerCertificate.PublicKey.Oid.Value) {
                case AlgorithmOid.ECC:
                    keyType = KeyType.EcDsa;
                    action = SignerCertificate.GetECDsaPrivateKey;
                    break;
                case AlgorithmOid.RSA:
                    keyType = KeyType.Rsa;
                    action = SignerCertificate.GetRSAPrivateKey;
                    break;
                case AlgorithmOid.DSA:
                    keyType = KeyType.Dsa;
                    // this one is silly, but .NET Standard 2.0 doesn't have X509Certificate2.GetDSAPrivateKey()
                    // extension method. Need a workaround.
                    phPubKey = SignerCertificate.PrivateKey;
                    break;
                default:
                    throw new NotSupportedException("Public key algorithm is not supported.");
            }
            if (action != null) {
                phPrivKey = action.Invoke();
            }
        }
    }

    #region Hash Signing
    Byte[] signHashEcDsa(Byte[] hash) {
        return ((ECDsa)phPrivKey).SignHash(hash);
    }
    Byte[] signHashDsa(Byte[] hash) {
        return ((DSA)phPrivKey).CreateSignature(hash);
    }
    Byte[] signHashRsa(Byte[] hash) {
        return ((RSA)phPrivKey).SignHash(hash, new HashAlgorithmName(hashAlgorithm.FriendlyName.ToUpper()), PaddingScheme);
    }
    #endregion

    #region signature validation
    Boolean verifyNullSigned(Byte[] hash, Byte[] signature) {
        if (hash.Length != signature.Length) {
            return false;
        }

        // performs exact binary comparison
        return !hash.Where((t, index) => t != signature[index]).Any();
    }
    Boolean verifyHashEcDsa(Byte[] hash, Byte[] signature) {
        return ((ECDsa)phPubKey).VerifyHash(hash, signature);
    }
    Boolean verifyHashRsa(Byte[] hash, Byte[] signature) {
        return ((RSA)phPubKey).VerifyHash(hash, signature, new HashAlgorithmName(hashAlgorithm.FriendlyName.ToUpper()), PaddingScheme);
    }
    Boolean verifyHashDsa(Byte[] hash, Byte[] signature) {
        return ((DSA)phPubKey).VerifySignature(hash, signature);
    }
    #endregion

    void getSignatureAlgorithm() {
        switch (keyType) {
            case KeyType.EcDsa:
                sigAlgorithm = new Oid($"{hashAlgorithm.FriendlyName}ECDSA"); // ECDSA
                break;
            case KeyType.Rsa:
                sigAlgorithm = PaddingScheme == RSASignaturePadding.Pss
                    ? new Oid(AlgorithmOid.RSA_PSS)                          // RSASSA-PSS
                    : new Oid($"{hashAlgorithm.FriendlyName}RSA");            // RSA
                break;
            case KeyType.Dsa:
                // DSA doesn't support PSS padding and hashing algorithm other than SHA1
                sigAlgorithm = new Oid(AlgorithmOid.SHA1_DSA);               // sha1DSA
                break;
            default:
                throw new NotSupportedException("Public key algorithm is not supported.");
        }
    }

    /// <summary>
    /// Signs the data with signer's private key and specified hash algorithm.
    /// </summary>
    /// <param name="message">Raw message to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>message</strong> parameter is null.</exception>
    /// <returns>Raw signature.</returns>
    /// <remarks>For DSA private key only SHA1 hash is used.</remarks>
    public Byte[] SignData(Byte[] message) {
        if (message == null) {
            throw new ArgumentNullException(nameof(message));
        }

        return SignHash(calculateHash(message));
    }
    /// <summary>
    /// Signs the hash with signer's private key.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> parameter is null.</exception>
    /// <returns>Raw signature.</returns>
    public Byte[] SignHash(Byte[] hash) {
        if (hash == null) {
            throw new ArgumentNullException(nameof(hash));
        }
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
                throw new InvalidOperationException(new Win32Exception(Win32ErrorCode.InvalidParameterException).Message);
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
        if (message == null) {
            throw new ArgumentNullException(nameof(message));
        }
        if (signature == null) {
            throw new ArgumentNullException(nameof(signature));
        }

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
        if (hash == null) {
            throw new ArgumentNullException(nameof(hash));
        }
        if (signature == null) {
            throw new ArgumentNullException(nameof(signature));
        }

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
                throw new NotSupportedException("Public key algorithm is not supported.");
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
        if (blob == null) {
            throw new ArgumentNullException(nameof(blob));
        }
        if (publicKey == null) {
            throw new ArgumentNullException(nameof(publicKey));
        }

        if (blob.BlobType != ContentBlobType.SignedBlob) {
            throw new InvalidOperationException("The blob is not signed.");
        }

        using var signerInfo = new CryptSigner();
        signerInfo.acquirePublicKey(publicKey.GetAsymmetricKeyPair());
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
        if (sigAlgorithm == null) {
            getSignatureAlgorithm();
        }
        Oid algId = sigAlgorithm;
        var parameters = new List<Byte>();
        switch (keyType) {
            case KeyType.EcDsa: // ECDSA
                if (alternate) {
                    // specifiedECDSA
                    algId = new Oid(AlgorithmOid.ECDSA_SPECIFIED); // only here we override algorithm OID
                    parameters
                        .AddRange(
                            new AlgorithmIdentifier(hashAlgorithm, new Asn1Null().GetRawData()).RawData
                        );
                }
                break;
            case KeyType.Rsa: // RSA
                              // only RSA supports parameters. For PKCS1 padding: NULL, for PSS padding: 
                              // RSASSA-PSS-params ::= SEQUENCE {
                              //     hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
                              //     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
                              //     saltLength         [2] INTEGER          DEFAULT 20,
                              //     trailerField       [3] TrailerField     DEFAULT trailerFieldBC
                              // }
                if (PaddingScheme == RSASignaturePadding.Pss) {
                    Byte[] hash = new AlgorithmIdentifier(hashAlgorithm, null).RawData;
                    parameters.AddRange(Asn1Utils.Encode(hash, 0xa0));
                    // mask generation function: mgf1
                    Byte[] mgf = new AlgorithmIdentifier(new Oid("1.2.840.113549.1.1.8"), hash).RawData;
                    parameters.AddRange(Asn1Utils.Encode(mgf, 0xa1));
                    // salt
                    parameters.AddRange(Asn1Utils.Encode(new Asn1Integer(20).GetRawData(), 0xa2));
                    // general PSS parameters encode
                    parameters = new List<Byte>(Asn1Utils.Encode(parameters.ToArray(), 48));
                } else {
                    parameters.AddRange(new Asn1Null().GetRawData());
                }
                break;
        }
        return new AlgorithmIdentifier(algId, parameters.ToArray());
    }

    #region IDisposable implementation
    void releaseUnmanagedResources() {
        // dispose key handle
        phPubKey?.Dispose();
        phPrivKey?.Dispose();
        //TODO: Crypt32.CertFreeCertificateContext(SignerCertificate.Handle);
        SignerCertificate = null;
    }
    /// <inheritdoc />
    public void Dispose() {
        releaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }
    /// <inheritdoc />
    ~CryptSigner() {
        releaseUnmanagedResources();
    }
    #endregion

    enum KeyType {
        EcDsa,
        Rsa,
        Dsa
    }
}
