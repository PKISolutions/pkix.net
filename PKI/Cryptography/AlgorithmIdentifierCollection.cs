using System;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Represents a collection of <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> objects.
    /// </summary>
    public class AlgorithmIdentifierCollection : BasicCollection<AlgorithmIdentifier> {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmIdentifierCollection"/> class without any <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> information.
        /// </summary>
        public AlgorithmIdentifierCollection() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmIdentifierCollection"/> class from an array of <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> objects.
        /// </summary>
        /// <param name="algIdentifiers">An array of <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> objects.</param>
        public AlgorithmIdentifierCollection(IEnumerable<AlgorithmIdentifier> algIdentifiers) : base(algIdentifiers) { }

        /// <summary>
        /// Gets an <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> object from the <see cref="AlgorithmIdentifierCollection"/> object by attributes object identifier.
        /// </summary>
        /// <param name="oid">A string that represents algorithm identifier.</param>
        /// <remarks>Use this property to retrieve an <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> object from an <see cref="AlgorithmIdentifierCollection"/>
        /// object if you know the value of the object identifier the <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/>
        /// object. You can use the <see cref="this[int]"/> property to retrieve an <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> object if you know
        /// its location in the collection</remarks>
        /// <returns>An <see cref="SysadminsLV.PKI.Cryptography.AlgorithmIdentifier"/> object.</returns>
        public AlgorithmIdentifier this[String oid] {
            get {
                return InternalList.FirstOrDefault(x => x.AlgorithmId.Value.Equals(oid, StringComparison.OrdinalIgnoreCase));
            }
        }
        /// <summary>
        /// Decodes ASN.1-encoded algorithm identifier collection.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array that represents algorithm identifier collection.</param>
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
                InternalList.Add(new AlgorithmIdentifier(asn.GetTagRawData()));
            } while (asn.MoveNextSibling());
        }
        /// <summary>
        /// Encodes current collection to an ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        /// <remarks>
        /// Algorithm identifier collection is an unordered list and outer ASN type is encoded as SET.
        /// <para>If there are no items in collection, an empty SET type is returned.</para>
        /// </remarks>
        public Byte[] Encode() {
            if (Count == 0) {
                return new Byte[] { 49, 0 };
            }
            var rawData = new List<Byte>();
            foreach (AlgorithmIdentifier algId in this) {
                rawData.AddRange(algId.RawData);
            }

            return Asn1Utils.Encode(rawData.ToArray(), 49);
        }
    }
}
