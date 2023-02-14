using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

public sealed class DsaPublicKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Public key algorithm is not DSA.";
    static readonly Oid _oid = new(AlgorithmOid.DSA);
    DSAParameters dsaParams;
    DSA dsa;

    public DsaPublicKey(PublicKey publicKey) : base(_oid, true) {
        if (publicKey == null) {
            throw new ArgumentNullException(nameof(publicKey));
        }
        if (publicKey.Oid.Value != Oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        decodeFromPublicKey(publicKey);
    }
    public DsaPublicKey(Byte[] rawData, KeyPkcsFormat keyFormat) : base(_oid, true) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        switch (keyFormat) {
            case KeyPkcsFormat.Pkcs1:
                decodePkcs8Key(rawData);
                break;
            case KeyPkcsFormat.Pkcs8:
                decodePkcs8Key(rawData);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    void decodeFromPublicKey(PublicKey publicKey) {
        dsaParams.Y = GetPositiveInteger(publicKey.EncodedKeyValue.RawData);
        decodeParams(publicKey.EncodedParameters.RawData);
    }
    void decodePkcs8Key(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextAndExpectTags(0x30);
        Int32 offset = asn.Offset;
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        if (oid.Value != _oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        asn.MoveNextAndExpectTags(0x30);
        decodeParams(asn.GetTagRawData());
        asn.Seek(offset);
        asn.MoveNextSiblingAndExpectTags(Asn1Type.BIT_STRING);
        var bitString = (Asn1BitString)asn.GetTagObject();
        dsaParams.Y = GetPositiveInteger(bitString.Value);
    }
    void decodeParams(Byte[] paramBytes) {
        var asn = new Asn1Reader(paramBytes);
        // P
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParams.P = GetPositiveInteger(asn.GetPayload());
        // Q
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParams.Q = GetPositiveInteger(asn.GetPayload());
        // G
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParams.G = GetPositiveInteger(asn.GetPayload());
    }

    public override AsymmetricAlgorithm GetAsymmetricKey() {
        dsa = DSA.Create();
        dsa.ImportParameters(dsaParams);
        return dsa;
    }
    public override void Dispose() {
        dsa?.Dispose();
    }
}