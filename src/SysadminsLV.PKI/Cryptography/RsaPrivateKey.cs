using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents an RSA private key object.
/// </summary>
public sealed class RsaPrivateKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Private key algorithm is not RSA.";
    static readonly Oid _oid = new(AlgorithmOid.RSA);
    RSAParameters rsaParameters;
    RSA rsaKey;

    /// <summary>
    /// Initializes a new instance of <strong>RsaPrivateKey</strong> from a PKCS#1 or unencrypted PKCS#8 format.
    /// </summary>
    /// <param name="privateKey">Private key in PKCS#1 or PKCS#8 format.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>privateKey</strong> parameter is null.
    /// </exception>
    public RsaPrivateKey(Byte[] privateKey) : base(_oid, false) {
        if (privateKey == null) {
            throw new ArgumentNullException(nameof(privateKey));
        }
        selectFormat(privateKey);
    }
    /// <summary>
    /// Initializes a new instance of <strong>RsaPrivateKey</strong> from an existing RSA key.
    /// </summary>
    /// <param name="rsa">RSA key object.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rsa</strong> parameter is null.
    /// </exception>
    public RsaPrivateKey(RSA rsa) : base(_oid, false) {
        rsaKey = rsa ?? throw new ArgumentNullException(nameof(rsa));
    }

    /// <summary>
    /// Gets the private key format.
    /// </summary>
    public KeyPkcsFormat KeyFormat { get; private set; }

    void selectFormat(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // version
        asn.MoveNext();
        // algID
        asn.MoveNext();
        if (asn.Tag == 0x30) {
            KeyFormat = KeyPkcsFormat.Pkcs8;
            decodePkcs8(rawData);
        } else {
            KeyFormat = KeyPkcsFormat.Pkcs1;
            decodePkcs1(rawData);
        }
    }
    void decodePkcs8(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // version
        asn.MoveNext();
        // algID
        asn.MoveNext();
        Int32 offset = asn.Offset;
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        if (oid.Value != Oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        asn.Seek(offset);
        asn.MoveNextSiblingAndExpectTags(Asn1Type.OCTET_STRING);
        decodePkcs1(asn.GetPayload());
    }
    void decodePkcs1(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // version. Must be 0
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        // modulus: Modulus
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.Modulus = GetPositiveInteger(asn.GetPayload());
        // publicExponent: Exponent
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.Exponent = asn.GetPayload();
        // privateExponent: D
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.D = GetPositiveInteger(asn.GetPayload());
        // prime1: P
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.P = GetPositiveInteger(asn.GetPayload());
        // prime2: Q
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.Q = GetPositiveInteger(asn.GetPayload());
        // exponent1: DP
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.DP = GetPositiveInteger(asn.GetPayload());
        // exponent2: DQ
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.DQ = GetPositiveInteger(asn.GetPayload());
        // coefficient: InverseQ
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        rsaParameters.InverseQ = GetPositiveInteger(asn.GetPayload());
        rsaKey = RSA.Create();
        rsaKey.ImportParameters(rsaParameters);
    }

    /// <inheritdoc />
    public override AsymmetricAlgorithm GetAsymmetricKey() {
        return rsaKey;
    }
    /// <inheritdoc />
    public override void Dispose() {
        rsaKey?.Dispose();
    }
}
/*
PKCS#8
------
PrivateKeyInfo ::= SEQUENCE {
  version         Version,
  algorithm       AlgorithmIdentifier,
  PrivateKey      OCTET STRING
}

PKCS#1
------
RSAPrivateKey ::= SEQUENCE {
     version Version,
     modulus INTEGER, -- n
     publicExponent INTEGER, -- e
     privateExponent INTEGER, -- d
     prime1 INTEGER, -- p
     prime2 INTEGER, -- q
     exponent1 INTEGER, -- d mod (p-1)
     exponent2 INTEGER, -- d mod (q-1)
     coefficient INTEGER -- (inverse of q) mod p }

   Version ::= INTEGER

*/
