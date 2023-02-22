using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines Authority Information Access extension (AIA). This extension is used by certificate chaining engine to build
/// certificate chain (retrieve issuer certificate) and/or to check current certificate revocation status by using
/// Online Certificate Status Protocol (OCSP).
/// </summary>
public sealed class X509AuthorityInformationAccessExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.AuthorityInformationAccess);
    readonly List<String> _aiaUrlStrings = new();
    readonly List<String> _ocspUrlStrings = new();

    internal X509AuthorityInformationAccessExtension(Byte[] rawData, Boolean critical)
        : base(_oid, rawData, critical) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        m_decode(rawData);
    }

    /// <summary>
    /// Initializes a new instance of the <strong>X509AuthorityInformationAccessExtension</strong> class.
    /// </summary>
    public X509AuthorityInformationAccessExtension() { Oid = _oid; }
    /// <summary>
    /// Initializes a new instance of the <strong>X509AuthorityInformationAccessExtension</strong> class using an
    /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
    /// </summary>
    /// <param name="authorityInfos">The encoded data to use to create the extension.</param>
    /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
    /// <exception cref="ArgumentException">The data in the <strong>authorityInfos</strong> parameter is not valid extension value.</exception>
    public X509AuthorityInformationAccessExtension(AsnEncodedData authorityInfos, Boolean critical) :
        this(authorityInfos.RawData,critical) { }
    /// <summary>
    /// Initializes a new instance of the <strong>X509AuthorityInformationAccessExtension</strong> class by using arrays of
    /// Certification Authority Issuer and Online Certificate Status Protocol (OCSP) URLs.
    /// </summary>
    /// <param name="authorityIssuer">An array of strings that point to a issuer certificate.</param>
    /// <param name="ocsp">An array of strings that point to a Online Certificate Status Protocol (OCSP) service locations.</param>
    /// <param name="ocspFirst">Specifies whether OCSP URLs should be placed first.</param>
    /// <exception cref="ArgumentNullException">Both <i>authorityIssuer</i> and <i>ocsp</i> parameters are null.</exception>
    public X509AuthorityInformationAccessExtension(String[] authorityIssuer, String[] ocsp, Boolean ocspFirst = false) {
        if (authorityIssuer != null || ocsp != null) {
            m_initialize(authorityIssuer, ocsp, ocspFirst);
        } else {
            throw new ArgumentNullException("Both 'authorityIssuer' and 'ocsp' parameters cannot be null", new Exception());
        }
    }

    /// <summary>
    /// Gets issuer certificate location URLs.
    /// </summary>
    public String[] CertificationAuthorityIssuer => _aiaUrlStrings.ToArray();
    /// <summary>
    /// Gets Online Certificate Status Protocol service location URLs.
    /// </summary>
    public String[] OnlineCertificateStatusProtocol => _ocspUrlStrings.ToArray();

    void m_initialize(IEnumerable<String> authorityIssuer, IEnumerable<String> ocsp, Boolean ocspFirst) {
        Oid = _oid;
        Critical = false;
        var aiaBuilder = Asn1Builder.Create();
        var ocspBuilder = Asn1Builder.Create();
        Byte[] aiaOidBytes = new Asn1ObjectIdentifier(new Oid("1.3.6.1.5.5.7.48.2")).GetRawData();
        Byte[] ocspOidBytes = new Asn1ObjectIdentifier(new Oid("1.3.6.1.5.5.7.48.1")).GetRawData();
        if (authorityIssuer != null) {
            foreach (Uri uri in authorityIssuer.Select(url => new Uri(url))) {
                aiaBuilder.AddSequence(x => {
                    x.AddDerData(aiaOidBytes);
                    return x.AddImplicit(6, Encoding.ASCII.GetBytes(uri.AbsoluteUri.Trim()), true);
                });
                _aiaUrlStrings.Add(uri.AbsoluteUri);
            }
        }
        if (ocsp != null) {
            foreach (Uri uri in ocsp.Select(url => new Uri(url))) {
                ocspBuilder.AddSequence(x => {
                    x.AddDerData(ocspOidBytes);
                    return x.AddImplicit(6, Encoding.ASCII.GetBytes(uri.AbsoluteUri.Trim()), true);
                });
                _ocspUrlStrings.Add(uri.AbsoluteUri);
            }
        }
        var builder = Asn1Builder.Create();
        if (ocspFirst) {
            builder
                .AddSequence(ocspBuilder.GetRawData())
                .AddSequence(aiaBuilder.GetRawData());
        } else {
            builder
                .AddSequence(aiaBuilder.GetRawData())
                .AddSequence(ocspBuilder.GetRawData());
        }
        RawData = builder.GetEncoded();
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNext();
        do {
            Int32 offset = asn.Offset;
            if (asn.Tag != 48) {
                throw new Asn1InvalidTagException(asn.Offset);
            }
            asn.MoveNext();
            String oidString = ((Asn1ObjectIdentifier)asn.GetTagObject()).Value.Value;
            asn.MoveNextAndExpectTags(0x86);
            switch (oidString) {
                case "1.3.6.1.5.5.7.48.2":
                    _aiaUrlStrings.Add(Encoding.ASCII.GetString(asn.GetPayload()));
                    break;
                case "1.3.6.1.5.5.7.48.1":
                    _ocspUrlStrings.Add(Encoding.ASCII.GetString(asn.GetPayload()));
                    break;
            }
            asn.Seek(offset);
        } while (asn.MoveNextSibling());
    }
}