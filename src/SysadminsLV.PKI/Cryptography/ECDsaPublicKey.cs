using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a ECDSA public key object.
/// </summary>
public sealed class ECDsaPublicKey : AsymmetricKeyPair {
    const String ALG_ERROR = "Public key algorithm is not from elliptic curve (ECC) group.";
    static readonly Oid _oid = new(AlgorithmOid.ECC);
    ECDsa ecdsaKey;

    /// <summary>
    /// Initializes a new instance of <strong>ECDsaPublicKey</strong> from a public key object.
    /// </summary>
    /// <param name="publicKey">A public key that represents ECDSA public key.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>publicKey</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Supplied public key is not ECDSA key.
    /// </exception>
    public ECDsaPublicKey(PublicKey publicKey) : base(_oid, true) {
        if (publicKey == null) {
            throw new ArgumentNullException(nameof(publicKey));
        }
        if (publicKey.Oid.Value != Oid.Value) {
            throw new ArgumentException(ALG_ERROR);
        }
        decodeFromPublicKey(publicKey);
    }
    /// <summary>
    /// Initializes a new instance of <strong>ECDsaPublicKey</strong> from an ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded ECDSA public key.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rawData</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    ///     <strong>keyFormat</strong> enumeration is out of range.
    /// </exception>
    public ECDsaPublicKey(Byte[] rawData) : base(_oid, true) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        decodePkcs8Key(rawData);
    }
    /// <summary>
    /// Initializes a new instance of <strong>ECDsaPublicKey</strong> from an existing ECDSA key instance.
    /// </summary>
    /// <param name="ecDsa">ECDSA key object.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>ecDsa</strong> parameter is null.
    /// </exception>
    public ECDsaPublicKey(ECDsa ecDsa) : base(_oid, true) {
        ecdsaKey = ecDsa ?? throw new ArgumentNullException(nameof(ecDsa));
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

    void decodeFromPublicKey(PublicKey publicKey) {
        // skip first byte as it is always 0x04 for ECDSA keys
        Byte[] key = publicKey.EncodedKeyValue.RawData.Skip(1).ToArray();
        // coordinates are halves of concatenated encoded key value
        // X is first half
        // Y is second half
        CoordinateX = key.Take(key.Length / 2).ToArray();
        CoordinateY = key.Skip(key.Length / 2).ToArray();
        CurveOid = new Asn1ObjectIdentifier(publicKey.EncodedParameters.RawData).Value;
    }
    void decodePkcs8Key(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextAndExpectTags(0x30);
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        Oid oid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        if (oid.Value != AlgorithmOid.ECC) {
            throw new ArgumentException(ALG_ERROR);
        }
        asn.MoveNextAndExpectTags(Asn1Type.OBJECT_IDENTIFIER);
        CurveOid = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value;
        asn.MoveNextAndExpectTags(Asn1Type.BIT_STRING);
        var bitString = (Asn1BitString)asn.GetTagObject();
        Byte[] key = bitString.Value.Skip(1).ToArray();
        // coordinates are halves of concatenated encoded key value
        // X is first half
        // Y is second half
        CoordinateX = key.Take(key.Length / 2).ToArray();
        CoordinateY = key.Skip(key.Length / 2).ToArray();
    }

    /// <inheritdoc />
    public override AsymmetricAlgorithm GetAsymmetricKey() {
        if (ecdsaKey != null) {
            return ecdsaKey;
        }
        var ecdsaParams = new ECParameters {
            Q = {
                X = CoordinateX,
                Y = CoordinateY
            },
            Curve = ECCurve.CreateFromOid(CurveOid)
        };
        ecdsaKey = ECDsa.Create();
        if (ecdsaKey == null) {
            throw new PlatformNotSupportedException();
        }
        ecdsaKey.ImportParameters(ecdsaParams);
        return ecdsaKey;
    }

    /// <inheritdoc />
    public override void Dispose() {
        ecdsaKey?.Dispose();
    }
}