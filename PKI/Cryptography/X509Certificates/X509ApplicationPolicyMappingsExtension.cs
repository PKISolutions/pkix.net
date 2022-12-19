using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents application policy mappings certificate extension.
    /// </summary>
    /// <remarks><see cref="X509Extension.Critical"/> member is always set to <strong>True</strong>.</remarks>
    public sealed class X509ApplicationPolicyMappingsExtension : X509Extension {
        readonly Oid _oid = new(X509ExtensionOid.ApplicationPolicyMappings);

        /// <summary>
        /// Initializes a new instance of the <strong>X509ApplicationPolicyMappingsExtension</strong> class from
        /// an <see cref="AsnEncodedData"/> object.
        /// </summary>
        /// <param name="mappings"></param>
        /// <exception cref="ArgumentNullException">
        /// <strong>mappings</strong> parameter is null.
        /// </exception>
        public X509ApplicationPolicyMappingsExtension(AsnEncodedData mappings) : base(
            X509ExtensionOid.ApplicationPolicyMappings, mappings.RawData, true) {
            if (mappings == null) { throw new ArgumentNullException(nameof(mappings)); }
            m_decode(mappings.RawData);
        }
        /// <summary>
        /// Initializes a new instance of the <strong>X509ApplicationPolicyMappingsExtension</strong> class from
        /// a collection of <see cref="OidMapping"/> objects.
        /// </summary>
        /// <param name="mappings">
        /// A collection of <see cref="OidMapping"/> objects.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <strong>mappings</strong> parameter is null or empty. Parameter must include at least one OID mapping
        /// object.
        /// </exception>
        public X509ApplicationPolicyMappingsExtension(OidMapping[] mappings) {
            if (mappings == null || mappings.Length < 1) {
                throw new ArgumentNullException(nameof(mappings));
            }
            m_initialize(mappings);
        }

        /// <summary>
        /// Gets a collection of policy mappings.
        /// </summary>
        public OidMapping[] OidMappings { get; private set; }

        void m_initialize(IEnumerable<OidMapping> mappings) {
            Oid = _oid;
            Critical = true;
            List<Byte> rawData = new List<Byte>();
            IEnumerable<OidMapping> oidMappings = mappings as OidMapping[] ?? mappings.ToArray();
            foreach (OidMapping mapping in oidMappings) {
                rawData.AddRange(mapping.Encode());
            }
            OidMappings = oidMappings.ToArray();
            RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
        }
        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            asn.MoveNext();
            List<OidMapping> mappings = new List<OidMapping>();
            do {
                mappings.Add(new OidMapping(asn.GetTagRawData()));
            } while (asn.MoveNextSibling());
            OidMappings = mappings.ToArray();
        }
    }
}
