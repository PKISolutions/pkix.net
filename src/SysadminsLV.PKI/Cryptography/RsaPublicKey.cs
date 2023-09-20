using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a RSA public key structure.
/// </summary>
public sealed class RsaPublicKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Public key algorithm is RSA.";
    static readonly Oid _oid = new(AlgorithmOid.RSA);
    RSA rsaKey;

    /// <summary>
    /// Initializes a new instance of <strong>RsaPublicKey</strong> from a public key object.
    /// </summary>
    /// <param name="publicKey">A public key that represents RSA public key.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>publicKey</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Supplied public key is not RSA key.
    /// </exception>
    public RsaPublicKey(PublicKey publicKey) : base(_oid, true) {
        if (publicKey == null) {
            throw new ArgumentNullException(nameof(publicKey));
        }
        if (publicKey.Oid.Value != Oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        decodePkcs1Key(publicKey.EncodedKeyValue.RawData);
    }
    /// <summary>
    /// Initializes a new instance of <strong>RsaPublicKey</strong> from an ASN.1-encoded byte array
    /// and key format.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded RSA public key.</param>
    /// <param name="keyFormat">RSA public key format.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rawData</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    ///     <strong>keyFormat</strong> enumeration is out of range.
    /// </exception>
    public RsaPublicKey(Byte[] rawData, KeyPkcsFormat keyFormat) : base(_oid, true) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        switch (keyFormat) {
            case KeyPkcsFormat.Pkcs1:
                decodePkcs1Key(rawData);
                break;
            case KeyPkcsFormat.Pkcs8:
                decodePkcs8Key(rawData);
                break;
            default: throw new ArgumentOutOfRangeException();
        }
    }
    /// <summary>
    /// Initializes a new instance of <strong>RsaPublicKey</strong> from an existing DSA key instance.
    /// </summary>
    /// <param name="rsa">DSA key object.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rsa</strong> parameter is null.
    /// </exception>
    public RsaPublicKey(RSA rsa) : base(_oid, true) {
        rsaKey = rsa ?? throw new ArgumentNullException(nameof(rsa));
    }

    /// <summary>
    /// Gets the public key modulus.
    /// </summary>
    public Byte[] Modulus { get; private set; }
    /// <summary>
    /// Gets public key public exponent.
    /// </summary>
    public Byte[] PublicExponent { get; private set; }

    void decodePkcs1Key(Byte[] rawPublicKey) {
        var asn = new Asn1Reader(rawPublicKey);
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        Modulus = DecodePositiveInteger(asn.GetPayload());
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        PublicExponent = asn.GetPayload();
    }
    void decodePkcs8Key(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextAndExpectTags(0x30);
        Int32 offset = asn.Offset;
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        if (oid.Value != Oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        asn.Seek(offset);
        asn.MoveNextSiblingAndExpectTags(Asn1Type.BIT_STRING);
        asn.MoveNextAndExpectTags(0x30);
        decodePkcs1Key(asn.GetTagRawData());
    }

    /// <inheritdoc />
    public override AsymmetricAlgorithm GetAsymmetricKey() {
        if (rsaKey != null) {
            return rsaKey;
        }
        var rsaParams = new RSAParameters {
            Modulus = Modulus,
            Exponent = PublicExponent
        };
        rsaKey = RSA.Create();
        rsaKey.ImportParameters(rsaParams);
        return rsaKey;
    }

    /// <inheritdoc />
    public override void Dispose() {
        rsaKey?.Dispose();
    }
}