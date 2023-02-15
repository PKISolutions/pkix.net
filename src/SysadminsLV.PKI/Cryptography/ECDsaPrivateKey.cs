using System;
using System.Linq;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

public sealed class ECDsaPrivateKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Private key algorithm is not from elliptic curve (ECC) group.";
    static readonly Oid _oid = new(AlgorithmOid.ECC);
    ECParameters ecParameters;
    ECDsa ecdsaKey;

    public ECDsaPrivateKey(Byte[] rawData) : base(_oid, false) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        decodePkcs8(rawData);
    }

    /// <summary>
    /// Gets the named curve object identifier.
    /// </summary>
    public Oid CurveOid { get; private set; }
    /// <summary>
    /// Gets the X coordinate of public key.
    /// </summary>
    public Byte[] CoordinateX { get; private set; }
    /// <summary>
    /// Gets the Y coordinate of public key.
    /// </summary>
    public Byte[] CoordinateY { get; private set; }

    void decodePkcs8(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // version
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        // AlgID
        asn.MoveNextAndExpectTags(0x30);
        decodeAlgID(asn.GetTagRawData());
        // private key
        asn.MoveNextSiblingAndExpectTags(Asn1Type.OCTET_STRING);
        decodePrivateKey(asn.GetPayload());
    }

    void decodeAlgID(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // ECC oid
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        if (oid.Value != _oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        // curve OID
        asn.MoveNextAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER, 0x30);
        switch (asn.Tag) {
            case (Byte)Asn1Type.OBJECT_IDENTIFIER:
                CurveOid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
                ecParameters.Curve = ECCurve.CreateFromOid(CurveOid);
                break;
            case 0x30:
                decodeECParameters(asn.GetTagRawData());
                break;
            default:
                throw new ArgumentException("Expected either, named curve or EC curve parameters");
        }
    }
    void decodePrivateKey(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // version. Must be 1
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        // raw private key
        asn.MoveNextAndExpectTags(Asn1Type.OCTET_STRING);
        ecParameters.D = asn.GetPayload();
        while (asn.MoveNextSibling()) {
            switch (asn.Tag) {
                case 0xa0:
                    decodeECParameters(asn.GetPayload());
                    break;
                case 0xa1:
                    decodePublicKey(asn.GetPayload());
                    break;
                default:
                    return;
            }
        }
    }
    void decodePublicKey(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        var bitString = (Asn1BitString)asn.GetTagObject();
        Byte[] key = bitString.Value.Skip(1).ToArray();
        // coordinates are halves of concatenated encoded key value
        // X is first half
        // Y is second half
        CoordinateX = key.Take(key.Length / 2).ToArray();
        CoordinateY = key.Skip(key.Length / 2).ToArray();
        ecParameters.Q.X = CoordinateX;
        ecParameters.Q.Y = CoordinateY;
    }
    void decodeECParameters(Byte[] rawData) {
        ecParameters.Curve.CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass;
        var asn = new Asn1Reader(rawData);
        // version. Must be 1
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        // fieldID
        asn.MoveNextAndExpectTags(0x30);
        decodeFieldID(asn.GetTagRawData());
        // curve
        asn.MoveNextSiblingAndExpectTags(0x30);
        decodeCurve(asn.GetTagRawData());
        // base -> ECPoint
        asn.MoveNextSiblingAndExpectTags(Asn1Type.OCTET_STRING);
        Byte[] key = asn.GetPayload().Skip(1).ToArray();
        // coordinates are halves of concatenated encoded key value
        // X is first half
        // Y is second half
        ecParameters.Curve.G.X = key.Take(key.Length / 2).ToArray();
        ecParameters.Curve.G.Y = key.Skip(key.Length / 2).ToArray();
        // order
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        ecParameters.Curve.Order = GetPositiveInteger(asn.GetPayload());
        // co-factor
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        ecParameters.Curve.Cofactor = asn.GetPayload();
    }
    void decodeFieldID(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // fieldID
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        switch (oid.Value) {
            case AlgorithmOid.ECDSA_PRIME1:
                asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
                ecParameters.Curve.Prime = GetPositiveInteger(asn.GetPayload());
                break;
            case AlgorithmOid.ECDSA_CHAR2:
                throw new NotImplementedException("CHARACTERISTIC-TWO field is not implemented.");
            default:
                throw new ArgumentException("Invalid FieldID. Must be either prime-field or characteristic-two-field.");
        }
    }
    void decodeCurve(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        // A
        asn.MoveNextAndExpectTags(Asn1Type.OCTET_STRING);
        ecParameters.Curve.A = asn.GetPayload();
        // B
        asn.MoveNextAndExpectTags(Asn1Type.OCTET_STRING);
        ecParameters.Curve.B = asn.GetPayload();
        // seed (optional)
        if (asn.MoveNext()) {
            var bitString = (Asn1BitString)asn.GetTagObject();
            ecParameters.Curve.Seed = bitString.Value;
        }
    }

    public override AsymmetricAlgorithm GetAsymmetricKey() {
        return ecdsaKey ??= ECDsa.Create(ecParameters);
    }
    public override void Dispose() {
        ecdsaKey?.Dispose();
    }
}
/*
-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----

PKCS#8
------
PrivateKeyInfo ::= SEQUENCE {
  version         Version,
  algorithm       AlgorithmIdentifier,
  PrivateKey      OCTET STRING
}

FieldID { FIELD-ID:IOSet } ::= SEQUENCE { -- Finite field
    fieldType FIELD-ID.&id({IOSet}),
    parameters FIELD-ID.&Type({IOSet}{@fieldType})
}
FieldTypes FIELD-ID ::= {
    { Prime-p IDENTIFIED BY prime-field } |
    { Characteristic-two IDENTIFIED BY characteristic-two-field },
    ...
}
FIELD-ID ::= TYPE-IDENTIFIER

Characteristic-two ::= SEQUENCE {
    m INTEGER, -- Field size 2^m
    basis CHARACTERISTIC-TWO.&id({BasisTypes}),
    parameters CHARACTERISTIC-TWO.&Type({BasisTypes}{@basis})
}

BasisTypes CHARACTERISTIC-TWO::= {
    { NULL IDENTIFIED BY gnBasis } |
    { Trinomial IDENTIFIED BY tpBasis } |
    { Pentanomial IDENTIFIED BY ppBasis },
    ...
}
Prime-p ::= INTEGER -- Field size p

Trinomial ::= INTEGER

Pentanomial ::= SEQUENCE {
    k1 INTEGER,
    k2 INTEGER,
    k3 INTEGER
}
CHARACTERISTIC-TWO ::= TYPE-IDENTIFIER

ECParameters ::= SEQUENCE {
    version INTEGER { ecpVer1(1) } (ecpVer1),
    fieldID FieldID {{FieldTypes}},
    curve Curve,
    base ECPoint,
    order INTEGER,
    cofactor INTEGER OPTIONAL,
    ...
}
Curve ::= SEQUENCE {
    a FieldElement,
    b FieldElement,
    seed BIT STRING OPTIONAL
}

ECParameters ::= CHOICE {
    namedCurve         OBJECT IDENTIFIER
    -- implicitCurve   NULL
    -- specifiedCurve  SpecifiedECDomain
}

ECPrivateKey ::= SEQUENCE {
     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     privateKey     OCTET STRING,
     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     publicKey  [1] BIT STRING OPTIONAL
}

*/
