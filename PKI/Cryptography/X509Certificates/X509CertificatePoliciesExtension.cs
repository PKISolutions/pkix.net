using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    ///		<strong>X509CertificatePoliciesExtension</strong> represents a X.509 Certificate Policies extension.
    ///		The certificate policies extension contains a sequence of one or more policy information terms, each
    ///		of which consists of an object identifier (OID) and optional qualifiers.
    /// </summary>
    public sealed class X509CertificatePoliciesExtension : X509Extension {
        readonly Oid _oid = new Oid(X509ExtensionOid.CertificatePolicies);

        internal X509CertificatePoliciesExtension(Byte[] rawData, Boolean critical)
            : base(X509ExtensionOid.CertificatePolicies, rawData, critical) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_decode(rawData);
        }
        
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificatePoliciesExtension</strong> class.
        /// </summary>
        public X509CertificatePoliciesExtension() { Oid = _oid; }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificatePoliciesExtension</strong> class using an
        /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="policies">The encoded data to use to create the extension.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <remarks>
        /// This constructor strictly checks whether the data in the <strong>policies</strong> parameter is valid
        /// extension value.
        /// </remarks>
        public X509CertificatePoliciesExtension(AsnEncodedData policies, Boolean critical) :
            this(policies.RawData, critical) { }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificatePoliciesExtension</strong> class from an array of certificate
        /// policies and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="policies">An array of certificate policies.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <exception cref="ArgumentNullException"><strong>polcies</strong> parameter is either null or empty.</exception>
        public X509CertificatePoliciesExtension(X509CertificatePolicyCollection policies, Boolean critical) {
            if (policies == null || policies.Count == 0) { throw new ArgumentNullException(nameof(policies)); }
            m_initialize(policies, critical);
        }
        
        /// <summary>
        /// Gets array of policies contained in the extension.
        /// </summary>
        public X509CertificatePolicyCollection Policies { get; private set; }

        void m_initialize(X509CertificatePolicyCollection policies, Boolean critical) {
            Oid = _oid;
            Policies = policies;
            Critical = critical;
            RawData = Policies.Encode();
        }
        void m_decode(Byte[] rawData) {
            Policies = new X509CertificatePolicyCollection();
            Policies.Decode(rawData);
        }
    }
}
