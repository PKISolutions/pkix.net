using System.Collections.Generic;
using System.IO;
using PKI.Exceptions;
using SysadminsLV.Asn1Parser;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a single certificate policy which consists of an object identifier (OID) and optional qualifiers.
    /// </summary>
    public class X509CertificatePolicy {
        readonly List<Byte> _rawData = new();
        readonly X509PolicyQualifierCollection _qualifiers = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="X509CertificatePolicy"/> class from a string that represents a
        /// policy OID value.
        /// </summary>
        /// <param name="policyOid">A string that represents certificate policy OID value.</param>
        /// <exception cref="ArgumentNullException"><strong>policyOid</strong> parameter is null or empty string.</exception>
        public X509CertificatePolicy(String policyOid) {
            if (String.IsNullOrEmpty(policyOid)) {
                throw new ArgumentNullException(nameof(policyOid));
            }
            m_initialize(policyOid);
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CertificatePolicy"/> class from a string that represents a
        /// policy OID value and an array of policy qualifiers that are associated with the specified policy OID.
        /// </summary>
        /// <param name="policyOid">A string that represents certificate policy OID value.</param>
        /// <param name="qualifiers">A collection of policy qualifiers.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>policyOid</strong> and/or <strong>qualifiers</strong> parameter is null or empty string.
        /// </exception>
        public X509CertificatePolicy(String policyOid, X509PolicyQualifierCollection qualifiers) {
            if (String.IsNullOrEmpty(policyOid)) {
                throw new ArgumentNullException(nameof(policyOid));
            }
            if (qualifiers == null) {
                throw new ArgumentNullException(nameof(qualifiers));
            }
            m_initialize(policyOid, qualifiers);
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CertificatePolicy"/> class from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array that represent encoded certificate policy.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
        /// <exception cref="InvalidDataException">The data in the <strong>rawData</strong> parameter is not valid
        /// certificate policy.</exception>
        public X509CertificatePolicy(Byte[] rawData) {
            if (rawData == null) {
                throw new ArgumentNullException(nameof(rawData));
            }
            m_decode(rawData);
        }

        /// <summary>
        /// Gets certificate policy object identifier (OID).
        /// </summary>
        public Oid PolicyOid { get; private set; }
        /// <summary>
        /// Gets an array of optional certificate policy qualifiers.
        /// </summary>
        public X509PolicyQualifierCollection PolicyQualifiers => new(_qualifiers);

        void m_initialize(String policyOid, X509PolicyQualifierCollection qualifiers = null) {
            _rawData.AddRange(Asn1Utils.EncodeObjectIdentifier(new Oid(policyOid)));
            PolicyOid = new Oid(policyOid);
            if (qualifiers != null) {
                _qualifiers.AddRange(qualifiers);
            }
        }
        void m_decode(Byte[] raw) {
            var asn = new Asn1Reader(raw);
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            asn.MoveNext();
            PolicyOid = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData());
            if (asn.MoveNext()) { _qualifiers.Decode(asn.GetTagRawData()); }
        }
        /// <summary>
        /// Adds policy qualifier to a <see cref="PolicyQualifiers"/> collection.
        /// </summary>
        /// <param name="policy">A policy qualifier to add.</param>
        public void Add(X509PolicyQualifier policy) {
            _qualifiers.Add(policy);
        }
        /// <summary>
        /// Removes policy qualifier from a <see cref="PolicyQualifiers"/> collection by using an item index in the collection.
        /// </summary>
        /// <param name="index">A zero-based item index in the collection.</param>
        /// <returns><strong>True</strong> if the policy qualifier is removed, otherwise <strong>False</strong>.</returns>
        public Boolean Remove(Int32 index) {
            try {
                _qualifiers.RemoveAt(index);
            } catch {
                return false;
            }

            return true;
        }
        /// <summary>
        /// Encodes certificate policy to a ASN.1-encoded byte array.
        /// </summary>
        /// <exception cref="UninitializedObjectException">
        /// An <see cref="X509CertificatePolicy"/> object is not initialized through any public constructor.
        /// </exception>
        /// <returns>ASN.1-encoded byte array.</returns>
        public Byte[] Encode() {
            if (PolicyOid == null) { throw new UninitializedObjectException(); }
            if (_qualifiers.Count > 0) {
                _rawData.AddRange(_qualifiers.Encode());
            }

            return Asn1Utils.Encode(_rawData.ToArray(), 48);
        }
    }
}
