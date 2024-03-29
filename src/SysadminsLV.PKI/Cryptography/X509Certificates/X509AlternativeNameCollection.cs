﻿using System;
using System.Collections.Generic;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a collection of <see cref="X509AlternativeName"/> objects.
/// </summary>
public class X509AlternativeNameCollection : BasicCollection<X509AlternativeName> {
    /// <summary>
    /// Initializes a new instance of the <see cref="X509AlternativeNameCollection"/> class without any <see cref="X509AlternativeName"/> information.
    /// </summary>
    public X509AlternativeNameCollection() { }
    /// <summary>
    /// Initializes a new instance of the <see cref="X509AlternativeNameCollection"/> class from an array of <see cref="X509AlternativeName"/> objects.
    /// </summary>
    /// <param name="names">An array of <see cref="X509AlternativeName"/> objects.</param>
    public X509AlternativeNameCollection(IEnumerable<X509AlternativeName> names) : base(names) { }

    /// <summary>
    /// Encodes an array of <see cref="X509AlternativeName"/> to an ASN.1-encoded byte array.
    /// </summary>
    /// <returns>ASN.1-encoded byte array.</returns>
    public Byte[] Encode() {
        var rawData = new List<Byte>();
        if (InternalList.Count == 0) { return null; }
        foreach (X509AlternativeName item in InternalList) {
            rawData.AddRange(item.RawData);
        }
        return Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    /// <summary>
    /// Decodes ASN.1 encoded byte array to an array of <see cref="X509AlternativeName"/> objects.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="PKI">
    ///     <strong>rawData</strong> parameter is null.
    /// </exception>
    /// <exception cref="SysadminsLV">
    /// The data in the <strong>rawData</strong> parameter is not valid array of <see cref="X509AlternativeName"/> objects.
    /// </exception>
    public void Decode(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        InternalList.Clear();
        var asn = new Asn1Reader(rawData);
        if (!asn.MoveNext()) {
            return;
        }
        do {
            InternalList.Add(new X509AlternativeName(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }
}