using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X500RdnAttribute"/> objects. For display purposes RDN attributes
    /// are stored in this collection in reverse order than they stored in binary form.
    /// </summary>
    public class X500RdnAttributeCollection : BasicCollection<X500RdnAttribute> {
        /// <summary>
        /// Encodes an array of <see cref="X500RdnAttribute"/> to an ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            List<Byte> rawData = new List<Byte>();
            if (InternalList.Count == 0) {
                return new Byte[] { 48, 0 };
            }
            for (Int32 i = InternalList.Count - 1; i >= 0; i--) {
                rawData.AddRange(Asn1Utils.Encode(InternalList[i].RawData, 49));
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1 encoded byte array to an array of <see cref="X500RdnAttribute"/> objects.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>rawData</strong> parameter is null.
        /// </exception>
        /// <exception cref="AccessViolationException">
        /// The collection is read-only and cannot be modified.
        /// </exception>
        /// <exception cref="Asn1InvalidTagException">
        /// The data in the <strong>rawData</strong> parameter is not valid array of <see cref="X500RdnAttribute"/> objects.
        /// </exception>
        public void Decode(Byte[] rawData) {
            if (IsReadOnly) {
                throw new AccessViolationException("An object is encoded and is write-protected.");
            }
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            InternalList.Clear();
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            if (!asn.MoveNext()) {
                return;
            }
            do {
                if (asn.Tag != 49) {
                    throw new Asn1InvalidTagException(asn.Offset);
                }
                InternalList.Add(new X500RdnAttribute(asn.GetPayload()));
            } while (asn.MoveNextSibling());
            // reverse list to get attributes from leaf to root.
            InternalList.Reverse();
        }
        /// <summary>
        /// Converts current collection to an instance of <see cref="X500DistinguishedName"/> class.
        /// </summary>
        /// <returns>An instance of <see cref="X500DistinguishedName"/> class.</returns>
        public X500DistinguishedName ToDistinguishedName() {
            return InternalList.Count == 0
                ? new X500DistinguishedName(new Byte[] { 48, 0 })
                : new X500DistinguishedName(Encode());
        }
        /// <summary>
        /// Gets an <see cref="X500RdnAttribute"/> object from the <see cref="X500RdnAttributeCollection"/> object.
        /// </summary>
        /// <param name="oid">The location of the <see cref="X500RdnAttribute"/> object in the collection.</param>
        /// <returns></returns>
        public X500RdnAttribute this[String oid] => InternalList.FirstOrDefault(x => x.Oid.Value.Equals(oid, StringComparison.InvariantCultureIgnoreCase));
    }
}