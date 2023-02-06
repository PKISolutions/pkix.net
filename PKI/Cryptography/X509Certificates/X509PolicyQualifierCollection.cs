using System.Collections.Generic;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a collection of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509PolicyQualifier"/> objects.
    /// </summary>
    public class X509PolicyQualifierCollection : BasicCollection<X509PolicyQualifier> {
        /// <inheritdoc />
        public X509PolicyQualifierCollection() { }
        /// <inheritdoc />
        public X509PolicyQualifierCollection(IEnumerable<X509PolicyQualifier> collection) : base(collection) { }

        /// <summary>
        /// Encodes an array of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509PolicyQualifier"/> to an ASN.1-encoded byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            if (InternalList.Count == 0) {
                return null;
            }
            Int32 index = 1;
            List<Byte> rawData = new List<Byte>();
            foreach (X509PolicyQualifier qualifier in InternalList) {
                if (qualifier.Type == X509PolicyQualifierType.UserNotice) {
                    qualifier.NoticeNumber = index;
                    index++;
                }
                rawData.AddRange(qualifier.Encode());
            }
            return Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        /// <summary>
        /// Decodes ASN.1 encoded byte array to an array of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509PolicyQualifier"/> objects.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// The data in the <strong>rawData</strong> parameter is not valid array of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.X509PolicyQualifier"/> objects.
        /// </exception>
        public void Decode(Byte[] rawData) {
            InternalList.Clear();
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            asn.MoveNext();
            do {
                InternalList.Add(new X509PolicyQualifier(asn.GetTagRawData()));
            } while (asn.MoveNextSibling());
        }
    }
}