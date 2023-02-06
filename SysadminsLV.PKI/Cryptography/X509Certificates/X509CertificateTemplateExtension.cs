using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines Microsoft proprietary X.509 extension that represents certificate template extension used by
/// Enterprise CA to store certificate template information. This extension is used by CAs and
/// certificate autoenrollment to perform certificate-based renewals.
/// </summary>
public sealed class X509CertificateTemplateExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.CertTemplateInfoV2);

    X509CertificateTemplateExtension(Byte[] rawData, Boolean critical) : base(_oid, rawData, critical) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        m_decode(rawData);
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateTemplateExtension</strong> class.
    /// </summary>
    public X509CertificateTemplateExtension() { Oid = _oid; }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateTemplateExtension</strong> class using an
    /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="templateInfo">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    /// <remarks>
    /// This constructor strictly checks whether the data in the <strong>templateInfo</strong> parameter is valid
    /// extension value.
    /// </remarks>
    public X509CertificateTemplateExtension(AsnEncodedData templateInfo, Boolean critical) :
        this(templateInfo.RawData, critical) { }
    /// <summary>
    /// Initializes a new instance of the <strong>X509CertificateTemplateExtension</strong> class by using
    /// certificate template information.
    /// </summary>
    /// <param name="oid">An OID of the certificate template.</param>
    /// <param name="majorVersion">A major version of the certificate template.</param>
    /// <param name="minorVersion">A minor version of the certificate template.</param>
    public X509CertificateTemplateExtension(Oid oid, Int32 majorVersion, Int32 minorVersion) {
        m_initialize(oid, majorVersion, minorVersion);
    }

    /// <summary>
    /// Gets certificate template OID value.
    /// </summary>
    public Oid TemplateOid { get; private set; }
    /// <summary>
    /// Gets certificate template major version.
    /// </summary>
    public Int32 MajorVersion { get; private set; }
    /// <summary>
    /// Gets certificate template minor version.
    /// </summary>
    public Int32 MinorVersion { get; private set; }

    void m_initialize(Oid oid, Int32 majorVersion, Int32 minorVersion) {
        Oid = _oid;
        TemplateOid = new Oid(oid.Value, oid.FriendlyName);
        MajorVersion = majorVersion;
        MinorVersion = minorVersion;
        var rawData = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(oid));
        rawData.AddRange(new Asn1Integer(majorVersion).RawData);
        rawData.AddRange(new Asn1Integer(minorVersion).RawData);
        RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        asn.MoveNextSiblingAndExpectTags((Byte)Asn1Type.OBJECT_IDENTIFIER);
        TemplateOid = new Asn1ObjectIdentifier(asn.GetTagRawData()).Value;
        asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
        MajorVersion = (Int32)new Asn1Integer(asn.GetTagRawData()).Value;
        asn.MoveNextAndExpectTags((Byte)Asn1Type.INTEGER);
        MinorVersion = (Int32)new Asn1Integer(asn.GetTagRawData()).Value;
        RawData = rawData.ToArray();
    }
}