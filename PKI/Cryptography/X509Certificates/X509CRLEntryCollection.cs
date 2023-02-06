using System.Collections.Generic;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="X509CRLEntry"/> objects.
    /// </summary>
    public class X509CRLEntryCollection : BasicCollection<X509CRLEntry> {
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CRLEntryCollection"/> class without any <see cref="X509CRLEntry"/> information.
        /// </summary>
        public X509CRLEntryCollection() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CRLEntryCollection"/> class from an array of
        /// <see cref="X509CRLEntry"/> objects and closes collection (makes it read-only).
        /// </summary>
        /// <param name="entries"></param>
        public X509CRLEntryCollection(IEnumerable<X509CRLEntry> entries) : base(entries) { }
        
        /// <summary>
        /// Encodes a collection of <see cref="X509CRLEntry"/> objects to a ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array. If the collection is empty, a <strong>NULL</strong> is returned.</returns>
        public Byte[] Encode() {
            if (InternalList.Count == 0) { return null; }
            var rawData = new List<Byte>();
            foreach (X509CRLEntry item in InternalList) {
                rawData.AddRange(item.Encode());
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes a ASN.1-encoded byte array that contains revoked certificate information to a collection.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">The encoded data is not valid.</exception>
        /// <exception cref="ArgumentNullException">The <strong>rawData</strong> parameter is null reference.</exception>
        /// <remarks>This method removes any existing entries in the collection before decoding.</remarks>
        public void Decode(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }

            Decode(new Asn1Reader(rawData));
        }
        /// <summary>
        /// Decodes a ASN.1-encoded byte array that contains revoked certificate information to a collection.
        /// </summary>
        /// <param name="asn">ASN.1 that points to the beginning of the CRL entry collection structure.</param>
        /// <exception cref="Asn1InvalidTagException">The encoded data is not valid.</exception>
        /// <exception cref="ArgumentNullException">The <strong>rawData</strong> parameter is null reference.</exception>
        /// <remarks>This method removes any existing entries in the collection before decoding.</remarks>
        public void Decode(Asn1Reader asn) {
            if (asn == null) {
                throw new ArgumentNullException(nameof(asn));
            }
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            Int32 offset = asn.Offset;
            InternalList.Clear();
            InternalList.Capacity = asn.GetNestedNodeCount();
            if (!asn.MoveNext()) {
                throw new Asn1InvalidTagException(asn.Offset);
            }

            do {
                InternalList.Add(new X509CRLEntry(asn));
            } while (asn.MoveNextSibling());
            
            asn.Seek(offset);
        }


        /// <summary>
        /// Gets an <see cref="X509CRLEntry"/> object from the <see cref="X509CRLEntryCollection"/> object by revoked certificate's
        /// serial number.
        /// </summary>
        /// <param name="serialNumber">A string that represents a <see cref="X509CRLEntry.SerialNumber">SerialNumber</see>
        /// property.</param>
        /// <remarks>Use this property to retrieve an <see cref="X509CRLEntry"/> object from an <see cref="X509CRLEntryCollection"/>
        /// object if you know the <see cref="X509CRLEntry.SerialNumber">SerialNumber</see> value of the <see cref="X509CRLEntry"/>
        /// object. You can use the <see cref="this[String]"/> property to retrieve an <see cref="X509CRLEntry"/> object if you know
        /// its location in the collection</remarks>
        /// <returns>An <see cref="X509CRLEntry"/> object.</returns>
        public X509CRLEntry this[String serialNumber] {
            get {
                foreach (X509CRLEntry entry in InternalList) {
                    if (String.Equals(entry.SerialNumber, serialNumber, StringComparison.CurrentCultureIgnoreCase)) { return entry; }
                }
                return null;
            }
        }
    }
}