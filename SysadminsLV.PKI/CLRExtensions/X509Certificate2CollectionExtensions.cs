using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Utils.CLRExtensions;

/// <summary>
/// Contains extension methods for <see cref="X509Certificate2Collection"/> class.
/// </summary>
public static class X509Certificate2CollectionExtensions {
    /// <summary>
    /// Encodes existing collection of certificates to ASN.1-encoded byte array.
    /// </summary>
    /// <param name="collection">Extension collection to encode.</param>
    /// <param name="enclosingByte"></param>
    /// <exception cref="ArgumentNullException"><strong>extensions</strong> parameter is null.</exception>
    /// <returns>ASN.1-encoded byte array.</returns>
    /// <remarks>
    /// This method is not the same as <see cref="X509Certificate2Collection.Export(X509ContentType)">
    /// X509Certificate2Collection.Export</see> method and outputs ASN.1-style collection.
    /// </remarks>
    public static Byte[] Encode(this X509Certificate2Collection collection, Byte enclosingByte = 48) {
        if (collection.Count == 0) {
            return new Byte[] { enclosingByte, 0 };
        }
        var rawData = new List<Byte>();
        foreach (X509Certificate2 cert in collection) {
            rawData.AddRange(cert.RawData);
        }

        return Asn1Utils.Encode(rawData.ToArray(), enclosingByte);
    }
    /// <summary>
    /// Decodes ASN.1-encoded byte array that represents a collection of <see cref="X509Certificate2"/> objects.
    /// </summary>
    /// <param name="collection">Destination collection where decoded certificates will be added.</param>
    /// <param name="rawData">ASN.1-encoded byte array that represents certificate collection.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>extensions</strong> and/or <strong>rawData</strong> parameter is null.
    /// </exception>
    /// <remarks>
    /// If current collection contains items, decoded items will be appended to existing items.
    /// <para>This method is not the same as <see cref="X509Certificate2Collection.Import(global::System.Byte[])">
    /// X509Certificate2Collection.Import</see> method and accepts ASN.1-style collection.</para>
    /// </remarks>
    /// 
    public static void Decode(this X509Certificate2Collection collection, Byte[] rawData) {
        if (collection == null) { throw new ArgumentNullException(nameof(collection)); }
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }

        var asn = new Asn1Reader(rawData);
        if (!asn.MoveNext() || asn.NextOffset == 0) {
            return;
        }
        do {
            collection.Add(new X509Certificate2(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }
}