using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a message to submit to Time-Stamp Authority (TSA).
/// </summary>
public class TspMessageImprint {
    readonly List<Byte> _msgHash = new();

    /// <summary>
    ///     Initializes a new instance of <strong>TspMessageImprint</strong> from hash algorithm and data to hash.
    /// </summary>
    /// <param name="hashAlgorithm">
    ///     A hash algorithm to hash the data.
    /// </param>
    /// <param name="data">
    ///     Data to hash.
    /// </param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>hashAlgorithm</strong> or <strong>data</strong> is null.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     <strong>hashAlgorithm</strong> is invalid hashing algorithm.
    /// </exception>
    public TspMessageImprint(Oid hashAlgorithm, Byte[] data) {
        if (hashAlgorithm == null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        if (data == null) {
            throw new ArgumentNullException(nameof(data));
        }
        encode(hashAlgorithm, data);
    }

    internal TspMessageImprint(Byte[] asnData) {
        if (asnData == null) {
            throw new ArgumentNullException(nameof(asnData));
        }
        decode(new Asn1Reader(asnData));
    }

    /// <summary>
    /// Gets the algorithm identifier object.
    /// </summary>
    public AlgorithmIdentifier AlgorithmIdentifier { get; private set; }
    /// <summary>
    /// Gets the hash of data.
    /// </summary>
    public Byte[] MessageHash => _msgHash.ToArray();

    void encode(Oid hashAlgorithm, Byte[] data) {
        using HashAlgorithm hasher = getAlgId(hashAlgorithm);
        _msgHash.AddRange(hasher.ComputeHash(data));
    }
    HashAlgorithm getAlgId(Oid hashAlgorithm) {
        var hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName);
        if (hasher == null) {
            throw new CryptographicException("Invalid hashing algorithm specified.");
        }
        var oid = new Oid(hashAlgorithm.Value);
        AlgorithmIdentifier = new AlgorithmIdentifier(oid, Array.Empty<Byte>());
        return hasher;
    }
    void decode(Asn1Reader asn) {
        asn.MoveNextAndExpectTags(48);
        AlgorithmIdentifier = new AlgorithmIdentifier(asn.GetTagRawData());
        asn.MoveNextSiblingAndExpectTags((Byte)Asn1Type.OCTET_STRING);
        _msgHash.AddRange(new Asn1OctetString(asn).Value);
    }

    /// <summary>
    /// Encodes current object to ASN.1-encoded byte array.
    /// </summary>
    /// <returns>
    /// ASN.1-encoded byte array.
    /// </returns>
    public Byte[] Encode() {
        return new Asn1Builder()
            .AddDerData(AlgorithmIdentifier.RawData)
            .AddOctetString(MessageHash)
            .GetEncoded();
    }


    /// <inheritdoc />
    public override String ToString() {
        var sb = new StringBuilder();
        sb.Append(
            $@"
Hash Algorithm: {AlgorithmIdentifier.AlgorithmId.Format(true)}
Hash Value :
    {AsnFormatter.BinaryToString(_msgHash.ToArray(), EncodingType.HexAddress).TrimEnd().Replace("\r\n", "\r\n    ")}
"
        );
        return sb.ToString();
    }
}