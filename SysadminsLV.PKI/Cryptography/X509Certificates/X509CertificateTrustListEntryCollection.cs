using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a collection of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificateTrustListEntry"/> objects.
/// </summary>
public class X509CertificateTrustListEntryCollection : BasicCollection<X509CertificateTrustListEntry> {
    /// <inheritdoc />
    public X509CertificateTrustListEntryCollection() { }
    /// <inheritdoc />
    public X509CertificateTrustListEntryCollection(IEnumerable<X509CertificateTrustListEntry> collection) : base(collection) { }

    /// <summary>
    /// Gets an <see cref="X509CertificateTrustListEntry"/> object from the <see cref="X509CertificateTrustListEntryCollection"/> object by certificate's
    /// Thumbprint value.
    /// </summary>
    /// <param name="thumbprint">A string that represents a <see cref="X509CertificateTrustListEntry.Thumbprint">Thumbprint</see> property.</param>
    /// <remarks>
    /// Use this property to retrieve an <see cref="X509CertificateTrustListEntry"/> object from an <see cref="X509CertificateTrustListEntryCollection"/>
    /// object if you know the <see cref="X509CertificateTrustListEntry.Thumbprint">Thumbprint</see> value of the <see cref="X509CertificateTrustListEntry"/>
    /// object. You can use the <see cref="this[Int32]"/> property to retrieve an <see cref="X509CertificateTrustListEntry"/> object if you know
    /// its location in the collection.
    /// </remarks>
    /// <returns>An <see cref="X509CertificateTrustListEntry"/> object if found, or <strong>null</strong> if specified item was not found.</returns>
    public X509CertificateTrustListEntry this[String thumbprint] {
        get {
            return InternalList.FirstOrDefault(x => x.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Encodes current collection to an ASN.1-encoded byte array.
    /// </summary>
    /// <returns>
    /// ASN.1-encoded byte array.
    /// </returns>
    public Byte[] Encode() {
        if (Count == 0) {
            return new Byte[] { 48, 0 };
        }
        var rawData = new List<Byte>();
        foreach (X509CertificateTrustListEntry entry in this) {
            rawData.AddRange(entry.Encode());
        }

        return Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    /// <summary>
    /// Decodes ASN.1-encoded certificate trust list collection.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents certificate trust list collection.</param>
    /// <exception cref="System.ArgumentNullException">
    /// <strong>rawData</strong> parameter is null.
    /// </exception>
    public void Decode(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        Clear();
        var asn = new Asn1Reader(rawData);
        if (asn.PayloadLength == 0) { return; }
        asn.MoveNext();
        do {
            var entry = new X509CertificateTrustListEntry(new AsnEncodedData(asn.GetTagRawData()));
            InternalList.Add(entry);
        } while (asn.MoveNextSibling());
    }
}