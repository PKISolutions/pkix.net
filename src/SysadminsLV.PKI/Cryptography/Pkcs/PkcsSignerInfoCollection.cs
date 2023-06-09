using System;
using System.Collections.Generic;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs;

/// <summary>
/// Represents a strongly-typed collection of <see cref="PkcsSignerInfo"/> objects.
/// </summary>
public class PkcsSignerInfoCollection : BasicCollection<PkcsSignerInfo> {
    /// <summary>
    /// Initializes a new instance of the <see cref="PkcsSignerInfoCollection"/> class without any <see cref="PkcsSignerInfo"/> information.
    /// </summary>
    public PkcsSignerInfoCollection() { }
    /// <summary>
    /// Initializes a new instance of the <see cref="PkcsSignerInfoCollection"/> class from an array of <see cref="PkcsSignerInfo"/> objects.
    /// </summary>
    /// <param name="signerInfos">An array of <see cref="PkcsSignerInfo"/> objects.</param>
    public PkcsSignerInfoCollection(IEnumerable<PkcsSignerInfo> signerInfos) : base(signerInfos) { }

    /// <summary>
    /// Decodes ASN.1-encoded signer info collection.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents signer info collection.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>rawData</strong> parameter is null.
    /// </exception>
    public void Decode(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        Clear();
        var asn = new Asn1Reader(rawData);
        if (asn.PayloadLength == 0) { return; }
        asn.MoveNext();
        do {
            InternalList.Add(new PkcsSignerInfo(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }
    /// <summary>
    /// Encodes current collection to an ASN.1-encoded byte array.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    /// <remarks>
    /// Signer info collection is an unordered list and outer ASN type is encoded as SET.
    /// <para>If there are no items in collection, an empty SET type is returned.</para>
    /// </remarks>
    public Byte[] Encode() {
        if (Count == 0) {
            return new Byte[] { 49, 0 };
        }
        var rawData = new List<Byte>();
        foreach (PkcsSignerInfo signerInfo in this) {
            rawData.AddRange(signerInfo.RawData);
        }

        return Asn1Utils.Encode(rawData.ToArray(), 49);
    }
}