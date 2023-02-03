using System.Collections.Generic;
using System.IO;
using System.Numerics;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.CLRExtensions;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents the X.509 Certificate Policy Constraints certificate extension. The policy constraints
    /// extension can be used in certificates issued to CAs.The policy constraints extension constrains
    /// path validation in two ways.  It can be used to prohibit policy mapping or require that each certificate
    /// in a path contain an acceptable policy identifier.
    /// </summary>
    public sealed class X509CertificatePolicyConstraintsExtension : X509Extension {
        readonly Oid _oid = new(X509ExtensionOid.CertificatePolicyConstraints);
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificatePolicyConstraintsExtension</strong> class from
        /// an <see cref="AsnEncodedData"/> object.
        /// </summary>
        /// <param name="constraints"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public X509CertificatePolicyConstraintsExtension(AsnEncodedData constraints)
            : base(X509ExtensionOid.CertificatePolicyConstraints, constraints.RawData, true){
            if (constraints == null) { throw new ArgumentNullException(nameof(constraints)); }
            m_decode(constraints.RawData);
        }

        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificatePolicyConstraintsExtension</strong> class from
        /// a minimum and maximum number of certificates with required certificate policy.
        /// </summary>
        /// <param name="explicitPolicy">
        /// The number of additional certificates that may appear in the path before an explicit policy
        /// is required for the entire path
        /// </param>
        /// <param name="inhibitPolicy">
        /// the number of additional certificates that may appear in the path before policy mapping is no
        /// longer permitted.
        /// </param>
        /// <exception cref="ArgumentException">
        /// Both, <strong>explicitPolicy</strong> and <strong>inhibitPolicy</strong> parameters cannot be NULL.
        /// </exception>
        public X509CertificatePolicyConstraintsExtension(Int32? explicitPolicy, Int32? inhibitPolicy) {
            if (explicitPolicy == null && inhibitPolicy == null) {
                throw new ArgumentException("All parameters 'explicitPolicy' and 'inhibitPolicy' cannot be NULL.");
            }
            m_initialize(explicitPolicy, inhibitPolicy);
        }

        /// <summary>
        /// Gets the number of additional certificates that may appear in the path before an explicit policy
        /// is required for the entire path. When an explicit policy is required, it is necessary for all
        /// certificates in the path to contain an acceptable policy identifier in the certificate policies
        /// extension.  An acceptable policy identifier is the identifier of a policy required by the user
        /// of the certification path or the identifier of a policy that has been declared equivalent through
        /// policy mapping.
        /// </summary>
        public Int32? RequireExplicitPolicy { get; private set; }
        /// <summary>
        /// Gets the number of additional certificates that may appear in the path before policy mapping is no
        /// longer permitted. For example, a value of one indicates that policy mapping may be processed in
        /// certificates issued by the subject of this certificate, but not in additional certificates in the path.
        /// </summary>
        public Int32? InhibitPolicyMapping { get; private set; }

        void m_initialize(Int32? explicitPolicy, Int32? inhibitPolicy) {
            Oid = _oid;
            Critical = true;
            List<Byte> rawData = new List<Byte>();
            if (explicitPolicy != null) {
                BigInteger integer = new BigInteger((Int32)explicitPolicy);
                rawData.AddRange(Asn1Utils.Encode(integer.ToLittleEndianByteArray(), 0x80));
                RequireExplicitPolicy = explicitPolicy;
            }
            if (inhibitPolicy != null) {
                BigInteger integer = new BigInteger((Int32)inhibitPolicy);
                rawData.AddRange(Asn1Utils.Encode(integer.ToLittleEndianByteArray(), 0x81));
                InhibitPolicyMapping = inhibitPolicy;
            }
            RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            asn.MoveNext();
            do {
                var integer = Asn1Utils.Encode(asn.GetPayload(), (Byte)Asn1Type.INTEGER);
                switch (asn.Tag) {
                    case 0x80: RequireExplicitPolicy = (Int32)Asn1Utils.DecodeInteger(integer); break;
                    case 0x81: InhibitPolicyMapping = (Int32)Asn1Utils.DecodeInteger(integer); break;
                    default: throw new InvalidDataException("The data is invalid");
                }
            } while (asn.MoveNextSibling());
        }
    }
}
