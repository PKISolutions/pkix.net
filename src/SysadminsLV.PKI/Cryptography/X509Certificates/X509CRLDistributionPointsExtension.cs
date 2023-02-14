using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines CRL Distribution Points (CDP) extension. This extension is used by a certificate chaining engine
/// to validate the certificate revocation status. Normally, this extension contains URLs to a issuer CRL
/// locations. 
/// </summary>
public sealed class X509CRLDistributionPointsExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.CRLDistributionPoints);
    readonly List<X509DistributionPoint> _distPoints = new();

    internal X509CRLDistributionPointsExtension(Byte[] rawData, Boolean critical) : base(_oid, rawData, critical) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        m_decode(rawData);
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLDistributionPointsExtension</strong> class.
    /// </summary>
    public X509CRLDistributionPointsExtension() { Oid = _oid; }
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
    public X509CRLDistributionPointsExtension(AsnEncodedData distributionPoints, Boolean critical) :
        this(distributionPoints.RawData, critical) { }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CRLDistributionPointsExtension</strong> class by using
    /// array of URL strings.
    /// </summary>
    /// <param name="urls">An array of CDP URLs.</param>
    /// <exception cref="ArgumentNullException"><strong>urls</strong>> parameter is null.</exception>
    public X509CRLDistributionPointsExtension(String[] urls) {
        if (urls == null) { throw new ArgumentNullException(nameof(urls)); }
        m_initialize(urls);
    }

    /// <summary>
    /// Gets CRL Distribution Points URLs.
    /// </summary>
    public X509DistributionPoint[] CRLDistributionPoints => _distPoints.ToArray();

    void m_initialize(IEnumerable<String> urls) {
        Oid = _oid;
        Critical = false;
        var rawData = new List<Byte>();
        Uri[] uris = urls.Select(url => new Uri(url)).ToArray();
        var cdp = new X509DistributionPoint(uris);
        _distPoints.Add(cdp);
        rawData.AddRange(Asn1Utils.Encode(_distPoints[0].RawData, 160));
        RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
        RawData = Asn1Utils.Encode(RawData, 48);
    }
    void m_decode (Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
        asn.MoveNext();
        do {
            _distPoints.Add(new X509DistributionPoint(asn.GetTagRawData()));
        } while (asn.MoveNextSibling());
    }

    /// <summary>
    /// Gets an array of certificate revocation list URLs listed in the extension.
    /// </summary>
    /// <returns>An array of URLs.</returns>
    public String[] GetURLs() {
        return _distPoints
            .SelectMany(x => x.FullName)
            .Where(x => x.Type == X509AlternativeNamesEnum.URL)
            .Select(x => x.Value)
            .ToArray();
    }
}