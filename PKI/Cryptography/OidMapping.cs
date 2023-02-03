using System.Collections.Generic;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.CLRExtensions;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace System.Security.Cryptography {
    /// <summary>
    /// Represents an object identifier (OID) mapping. OID mapping is used to map external OID from foreign
    /// domain to its equivalent in the subject domain.
    /// <para>
    /// OID mapping is usually used in Certificate and Application Policies Mappings certificate extensions.
    /// </para>
    /// </summary>
    public class OidMapping {
        /// <summary>
        /// Initializes a new instance of the <strong>OidMapping</strong> class from an Object Identifier pair.
        /// </summary>
        /// <param name="issuerOid">Represents an OID from external domain.</param>
        /// <param name="subjectOid">Represents a subject domain's equivalent OID.</param>
        /// <exception cref="ArgumentException">
        /// Either, <strong>issuerOid</strong> or <strong>subjectOid</strong> is not valid object identifier.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// Either, <strong>issuerOid</strong> or <strong>subjectOid</strong> is null.
        /// </exception>
        public OidMapping(Oid issuerOid, Oid subjectOid) {
            if (issuerOid == null) { throw new ArgumentNullException(nameof(issuerOid)); }
            if (subjectOid == null) { throw new ArgumentNullException(nameof(subjectOid)); }
            if (String.IsNullOrEmpty(issuerOid.Value) || String.IsNullOrEmpty(subjectOid.Value)) {
                throw new ArgumentException("Oid value cannot be empty");
            }
            IssuerDomainOid = issuerOid;
            SubjectDomainOid = subjectOid;
        }

        /// <summary>
        /// Initializes a new instance of the <strong>OidMapping</strong> class from an ASN.1-encoded byte array.
        /// </summary>
        /// <param name="asnData">ASN.1-encoded byte array.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public OidMapping(Byte[] asnData) {
            if (asnData == null) { throw new ArgumentNullException(nameof(asnData)); }
            m_decode(asnData);
        }

        /// <summary>
        /// Object Identifier from external domain.
        /// </summary>
        public Oid IssuerDomainOid { get; private set; }
        /// <summary>
        /// a subject domain's equivalent object identifier.
        /// </summary>
        public Oid SubjectDomainOid { get; private set; }
        
        void m_decode(Byte[] asnData) {
            Asn1Reader asn = new Asn1Reader(asnData);
            asn.MoveNext();
            IssuerDomainOid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
            asn.MoveNext();
            SubjectDomainOid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
        }

        /// <summary>
        /// Gets ASN.1-encoded byte array that represents OID mapping.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            List<Byte> entry = new List<Byte>();
            entry.AddRange(Asn1Utils.EncodeObjectIdentifier(IssuerDomainOid));
            entry.AddRange(Asn1Utils.EncodeObjectIdentifier(SubjectDomainOid));
            return Asn1Utils.Encode(entry.ToArray(), 48);
        }
        /// <summary>
        /// Gets textual representation of the current object.
        /// </summary>
        /// <param name="multiline">Specifies whether output is formatted in multiple lines.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public String Format(Boolean multiline) {
            return multiline
                ? $"Issuer Domain={IssuerDomainOid.Format(false)}\r\nSubject Domain={SubjectDomainOid.Format(false)}"
                : $"Issuer Domain={IssuerDomainOid.Format(false)}, Subject Domain={SubjectDomainOid.Format(false)}";
        }
    }
}
