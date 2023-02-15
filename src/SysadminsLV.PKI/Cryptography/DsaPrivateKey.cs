using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

public sealed class DsaPrivateKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Private key is not DSA.";
    static readonly Oid _oid = new(AlgorithmOid.DSA);
    DSAParameters dsaParameters;
    DSA dsaKey;

    public DsaPrivateKey(Byte[] privateKey) : base(_oid, false) {
        if (privateKey == null) {
            throw new ArgumentNullException(nameof(privateKey));
        }
        decode(privateKey);
    }

    public KeyPkcsFormat KeyFormat { get; private set; }

    void getPublicExponent() {
        // DSS public exponent (y) is: y = g^x mod p
        List<Byte> gCopy = dsaParameters.G.ToList();
        gCopy.Insert(0, 0);
        gCopy.Reverse();
        BigInteger g = bigIntegerFromParameter(dsaParameters.G);
        BigInteger x = bigIntegerFromParameter(dsaParameters.X);
        BigInteger p = bigIntegerFromParameter(dsaParameters.P);
        BigInteger y = BigInteger.ModPow(g, x, p);
        dsaParameters.Y = GetPositiveInteger(y.ToByteArray().Reverse().ToArray());
    }
    static BigInteger bigIntegerFromParameter(Byte[] parameter) {
        List<Byte> arr = parameter.ToList();
        if (arr[0] > 127) {
            arr.Insert(0, 0);
        }
        arr.Reverse();
        return new BigInteger(arr.ToArray());
    }
    void decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // version. Must be 0
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        Int32 offset = asn.Offset;
        // algID or params
        asn.MoveNextAndExpectTags(0x30, (Byte)Asn1Type.INTEGER);
        if (asn.Tag == 0x30) {
            decodePkcs8(asn);
        } else {
            asn.Seek(offset);
            decodePkcs1(asn);
        }
    }
    void decodePkcs1(Asn1Reader asn) {
        KeyFormat = KeyPkcsFormat.Pkcs1;
        decodeParams(asn);
        // y public exponent
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParameters.Y = GetPositiveInteger(asn.GetPayload());
        // x private exponent
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParameters.X = GetPositiveInteger(asn.GetPayload());
    }
    void decodePkcs8(Asn1Reader asn) {
        KeyFormat = KeyPkcsFormat.Pkcs8;
        // algID
        decodeAlgID(asn);
        // params
        asn.MoveNextAndExpectTags(0x30);
        decodeParams(asn);
        // PrivateKey
        asn.MoveNextAndExpectTags(Asn1Type.OCTET_STRING);
        decodePrivateKey(asn.GetPayload());
        getPublicExponent();
    }
    void decodeAlgID(Asn1Reader asn) {
        // DSA oid
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        if (oid.Value != _oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
    }
    void decodeParams(Asn1Reader asn) {
        // modulus p
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParameters.P = GetPositiveInteger(asn.GetPayload());
        // modulus q
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParameters.Q = GetPositiveInteger(asn.GetPayload());
        // base g
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParameters.G = GetPositiveInteger(asn.GetPayload());
    }
    void decodePrivateKey(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        dsaParameters.X = GetPositiveInteger(asn.GetPayload());
    }

    public override AsymmetricAlgorithm GetAsymmetricKey() {
        if (dsaKey != null) {
            return dsaKey;
        }
        dsaKey = DSA.Create();
        dsaKey.ImportParameters(dsaParameters);
        return dsaKey;
    }

    /// <inheritdoc />
    public override void Dispose() {
        dsaKey?.Dispose();
    }
}
/*
*** PKCS#1 ***
DSSPrivatKey_OpenSSL ::= SEQUENCE
  version INTEGER,
  p INTEGER,
  q INTEGER,
  g INTEGER,
  y INTEGER,
  x INTEGER
}
*** PKCS#8 ***
PrivateKeyInfo ::= SEQUENCE {
  version Version,
  algorithm AlgorithmIdentifier,
  PrivateKey OCTETSTRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm ALGORITHM.id,
  parameters Dss-Parms
}

Dss-Parms ::= SEQUENCE {
  p INTEGER,
  q INTEGER,
  g INTEGER
}

DSAPrivateKey ::= OCTETSTRING {
  privateExponent INTEGER
}
 */

