using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a DSA public key structure.
/// </summary>
public sealed class DsaPublicKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Public key algorithm is not DSA.";
    static readonly Oid _oid = new(AlgorithmOid.DSA);
    DSAParameters dsaParams;
    DSA dsaKey;

    /// <summary>
    /// Initializes a new instance of <strong>DsaPublicKey</strong> from a public key object.
    /// </summary>
    /// <param name="publicKey">A public key that represents DSA public key.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>publicKey</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Supplied public key is not DSA key.
    /// </exception>
    public DsaPublicKey(PublicKey publicKey) : base(_oid, true) {
        if (publicKey == null) {
            throw new ArgumentNullException(nameof(publicKey));
        }
        if (publicKey.Oid.Value != Oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        decodeFromPublicKey(publicKey);
    }
    /// <summary>
    /// Initializes a new instance of <strong>DsaPublicKey</strong> from an ASN.1-encoded byte array
    /// and key format.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded DSA public key.</param>
    /// <param name="keyFormat">DSA public key format.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rawData</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    ///     <strong>keyFormat</strong> enumeration is out of range.
    /// </exception>
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
                throw new ArgumentOutOfRangeException(nameof(keyFormat));
        }
    }
    /// <summary>
    /// Initializes a new instance of <strong>DsaPublicKey</strong> from an existing DSA key instance.
    /// </summary>
    /// <param name="dsa">DSA key object.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>dsa</strong> parameter is null.
    /// </exception>
    public DsaPublicKey(DSA dsa) : base(_oid, true) {
        dsaKey = dsa ?? throw new ArgumentNullException(nameof(dsa));
    }

    void decodeFromPublicKey(PublicKey publicKey) {
        var asn = new Asn1Reader(publicKey.EncodedKeyValue.RawData);
        dsaParams.Y = DecodePositiveInteger(asn.GetPayload());
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
        dsaParams.Y = DecodePositiveInteger(bitString.Value);
    }
    void decodeParams(Byte[] paramBytes) {
        var asn = new Asn1Reader(paramBytes);
        // P
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParams.P = DecodePositiveInteger(asn.GetPayload());
        // Q
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParams.Q = DecodePositiveInteger(asn.GetPayload());
        // G
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        dsaParams.G = DecodePositiveInteger(asn.GetPayload());
    }

    /// <inheritdoc />
    public override AsymmetricAlgorithm GetAsymmetricKey() {
        if (dsaKey != null) {
            return dsaKey;
        }
        dsaKey = DSA.Create();
        dsaKey.ImportParameters(dsaParams);
        return dsaKey;
    }
    /// <inheritdoc />
    public override void Dispose() {
        dsaKey?.Dispose();
    }
}