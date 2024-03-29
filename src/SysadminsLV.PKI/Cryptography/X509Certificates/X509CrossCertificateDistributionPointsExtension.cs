﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

#region asn module
//CrossCertDistPoints ::= SEQUENCE {
//    syncDeltaTime INTEGER(0..4294967295) OPTIONAL,
//    crossCertDistPointNames     CrossCertDistPointNames
//}
//CrossCertDistPointNames::= SEQUENCE OF GeneralNames

#endregion

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents Cross-Certificate Distribution Points certificate extension. The cross certificate distribution
/// point (Cross-CDP) extension identifies where cross certificates related to a particular certificate can be
/// obtained and how often that location is updated. Windows XP and later operating systems use this extension
/// for the discovery of cross-certificates that might be used during the path discovery and chain building
/// process.  
/// </summary>
public sealed class X509CrossCertificateDistributionPointsExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.CrossCDP);
    readonly X509AlternativeNameCollection _distPoints = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CrossCertificateDistributionPointsExtension"/> class
    /// using an <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="crossCertPoints">The encoded data to use to create the extension.</param>
    /// <param name="critical">
    ///		<strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
    /// </param>
    /// <exception cref="ArgumentException">
    ///		The data in the <strong>distributionPoints</strong> parameter is not valid extension value.
    /// </exception>
    public X509CrossCertificateDistributionPointsExtension(AsnEncodedData crossCertPoints, Boolean critical) : base(_oid, crossCertPoints.RawData, critical) {
        if (crossCertPoints == null) {
            throw new ArgumentNullException(nameof(crossCertPoints));
        }
        m_decode(crossCertPoints.RawData);
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509CrossCertificateDistributionPointsExtension</strong> class by using
    /// array of URL strings.
    /// </summary>
    /// <param name="urls">An array of CDP URLs.</param>
    /// <param name="syncDeltaTime">
    ///     The value that specifies the delta between when this location will be refreshed
    /// </param>
    /// <param name="critical">
    ///     <strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.
    /// </param>
    /// <exception cref="ArgumentNullException"><strong>urls</strong>> parameter is null.</exception>
    public X509CrossCertificateDistributionPointsExtension(String[] urls, Int32? syncDeltaTime, Boolean critical) {
        if (urls == null) {
            throw new ArgumentNullException(nameof(urls));
        }
        m_initialize(urls, syncDeltaTime, critical);
    }

    /// <summary>
    /// Gets an optional integer field that specifies the delta between when this location will be refreshed.
    /// </summary>
    public Int32? DeltaSyncTimeInSeconds { get; private set; }
    /// <summary>
    /// Gets an array of Cross-Certificate Distribution Points.
    /// </summary>
    public X509AlternativeNameCollection CrossCertDistributionPoints => new(_distPoints);

    void m_initialize(IEnumerable<String> urls, Int32? syncDeltaTime, Boolean critical) {
        Oid = _oid;
        Critical = critical;
        DeltaSyncTimeInSeconds = syncDeltaTime;

        var builder = Asn1Builder.Create();
        if (DeltaSyncTimeInSeconds != null) {
            builder.AddInteger(DeltaSyncTimeInSeconds.Value);
        }
        Uri[] uris = urls.Select(url => new Uri(url)).ToArray();
        foreach (Uri url in uris) {
            _distPoints.Add(new X509AlternativeName(X509AlternativeNamesEnum.URL, url));
        }
        builder.AddSequence(CrossCertDistributionPoints.Encode());
        RawData = builder.GetEncoded();
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNext();
        if (asn.Tag == (Byte)Asn1Type.INTEGER) {
            DeltaSyncTimeInSeconds = (Int32)((Asn1Integer)asn.GetTagObject()).Value;
            asn.MoveNext();
        }
        asn.MoveNext();
        do {
            var altNames = new X509AlternativeNameCollection();
            altNames.Decode(asn.GetTagRawData());
            _distPoints.AddRange(altNames);
        } while (asn.MoveNextSibling());
    }

    /// <summary>
    /// Gets an array of cross-certificate URL strings listed in the extension.
    /// </summary>
    /// <returns>An array of URLs.</returns>
    public String[] GetUrLs() {
        return _distPoints
            .Where(x => x.Type == X509AlternativeNamesEnum.URL)
            .Select(x => x.Value)
            .ToArray();
    }
}