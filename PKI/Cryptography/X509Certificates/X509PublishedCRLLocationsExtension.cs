using System.Collections.Generic;
using System.Linq;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Defines Published CRL Locations extension. This extension is included in CRLs and is used by
    /// a certification authority to provide information about CRL publication location in Active Directory.
    /// </summary>
    public sealed class X509PublishedCrlLocationsExtension : X509Extension {
        readonly Oid _oid = new Oid(X509ExtensionOid.PublishedCrlLocations);

        internal X509PublishedCrlLocationsExtension(Byte[] rawData, Boolean critical)
            : base(X509ExtensionOid.PublishedCrlLocations, rawData, critical) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_decode(rawData);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509CRLDistributionPointsExtension"/> class using an
        /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="distributionPoints">The encoded data to use to create the extension.</param>
        /// <param name="critical">
        ///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
        /// </param>
        /// <exception cref="ArgumentException">
        ///		The data in the <strong>distributionPoints</strong> parameter is not valid extension value.
        /// </exception>
        public X509PublishedCrlLocationsExtension(AsnEncodedData distributionPoints, Boolean critical) :
            this(distributionPoints.RawData, critical) { }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CRLDistributionPointsExtension</strong> class by using
        /// array of URL strings.
        /// </summary>
        /// <param name="urls">An array of CDP URLs.</param>
        /// <param name="critical">
        ///     <strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>urls</strong>> parameter is null.</exception>
        public X509PublishedCrlLocationsExtension(String[] urls, Boolean critical) {
            if (urls == null) { throw new ArgumentNullException(nameof(urls)); }
            m_initialize(urls, critical);
        }

        /// <summary>
        /// Gets CRL Distribution Points URLs.
        /// </summary>
        public X509DistributionPoint[] CRLDistributionPoints { get; private set; }

        void m_initialize(IEnumerable<String> urls, Boolean critical) {
            Oid = _oid;
            Critical = critical;
            List<Byte> rawData = new List<Byte>();
            Uri[] uris = urls.Select(url => new Uri(url)).ToArray();
            List<X509DistributionPoint> cdps = new List<X509DistributionPoint>(1);
            var cdp = new X509DistributionPoint(uris);
            cdps.Add(cdp);
            rawData.AddRange(Asn1Utils.Encode(cdps[0].RawData, 160));
            RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
            RawData = Asn1Utils.Encode(RawData, 48);
            CRLDistributionPoints = cdps.ToArray();
        }
        void m_decode(Byte[] rawData) {
            List<X509DistributionPoint> urls = new List<X509DistributionPoint>();
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            asn.MoveNext();
            do {
                urls.Add(new X509DistributionPoint(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
            CRLDistributionPoints = urls.ToArray();
        }

        /// <summary>
        /// Gets an array of certificate revocation list URLs listed in the extension.
        /// </summary>
        /// <returns>An array of URLs.</returns>
        public String[] GetUrLs() {
            List<String> urls = new List<String>();
            foreach (X509DistributionPoint crldp in CRLDistributionPoints) {
                urls.AddRange(from X509AlternativeName url in crldp.FullName where url.Type == X509AlternativeNamesEnum.URL select url.Value);
            }
            return urls.ToArray();
        }
    }
}
