using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.Pkcs;
/// <summary>
/// Represents a collection of <see cref="Pkcs9AttributeObject"/> objects.
/// </summary>
public class Pkcs9AttributeObjectCollection : BasicCollection<Pkcs9AttributeObject> {
    /// <inheritdoc />
    public Pkcs9AttributeObjectCollection() { }
    /// <inheritdoc />
    public Pkcs9AttributeObjectCollection(IEnumerable<Pkcs9AttributeObject> collection) : base(collection) { }

    /// <summary>
    /// Gets an <see cref="Pkcs9AttributeObject"/> object from the <see cref="Pkcs9AttributeObjectCollection"/> object by attributes object identifier.
    /// </summary>
    /// <param name="oid">A string that represents an attribute's object identifier.</param>
    /// <remarks>Use this property to retrieve an <see cref="Pkcs9AttributeObject"/> object from an <see cref="Pkcs9AttributeObjectCollection"/>
    /// object if you know the value of the object identifier the <see cref="Pkcs9AttributeObject"/>
    /// object. You can use the <see cref="this[String]"/> property to retrieve an <see cref="Pkcs9AttributeObject"/> object if you know
    /// its location in the collection</remarks>
    /// <returns>An <see cref="Pkcs9AttributeObject"/> object.</returns>
    public Pkcs9AttributeObject this[String oid] {
        get {
            return InternalList.FirstOrDefault(x => x.Oid.Value.Equals(oid, StringComparison.OrdinalIgnoreCase));
        }
    }
    /// <summary>
    /// Decodes ASN.1-encoded attribute collection.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents attribute collection.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>rawData</strong> parameter is null.
    /// </exception>
    public void Decode(Byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        Clear();
        var asn = new Asn1Reader(rawData);
        if (asn.PayloadLength == 0) {
            return;
        }
        
        asn.MoveNext();
        do {
            InternalList.Add(Pkcs9AttributeObjectFactory.CreateFromAsn1(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }
    /// <summary>
    /// Encodes current collection to an ASN.1-encoded byte array.
    /// </summary>
    /// <returns></returns>
    public Byte[] Encode() {
        if (Count == 0) {
            return Array.Empty<Byte>();
        }
        var rawData = new List<Byte>();
        foreach (Pkcs9AttributeObject attribute in this) {
            rawData.AddRange(attribute.Encode());
        }

        return Asn1Utils.Encode(rawData.ToArray(), 0x30);
    }
}
