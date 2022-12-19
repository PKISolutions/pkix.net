using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI;

namespace System.Security.Cryptography {
    /// <summary>
    /// Represents a collection of <see cref="X509Attribute"/> objects.
    /// </summary>
    public class X509AttributeCollection : BasicCollection<X509Attribute> {

        /// <summary>
        /// Initializes a new instance of the <see cref="X509AttributeCollection"/> class without any <see cref="X509Attribute"/> information.
        /// </summary>
        public X509AttributeCollection() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509AttributeCollection"/> class from an array of <see cref="X509Attribute"/> objects.
        /// </summary>
        /// <param name="attributes">An array of <see cref="X509Attribute"/> objects.</param>
        public X509AttributeCollection(IEnumerable<X509Attribute> attributes) : base(attributes) { }

        /// <summary>
        /// Gets an <see cref="X509Attribute"/> object from the <see cref="X509AttributeCollection"/> object by attributes object identifier.
        /// </summary>
        /// <param name="oid">A string that represents an attribute's object identifier.</param>
        /// <remarks>Use this property to retrieve an <see cref="X509Attribute"/> object from an <see cref="X509AttributeCollection"/>
        /// object if you know the value of the object identifier the <see cref="X509Attribute"/>
        /// object. You can use the <see cref="this[string]"/> property to retrieve an <see cref="X509Attribute"/> object if you know
        /// its location in the collection</remarks>
        /// <returns>An <see cref="X509Attribute"/> object.</returns>
        public X509Attribute this[String oid] {
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
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            Clear();
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.PayloadLength == 0) { return; }
            asn.MoveNext();
            do {
                InternalList.Add(X509Attribute.Decode(asn.GetTagRawData()));
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
            foreach (X509Attribute attribute in this) {
                rawData.AddRange(attribute.Encode());
            }

            return Asn1Utils.Encode(rawData.ToArray(), 0x30);
        }
    }
}
