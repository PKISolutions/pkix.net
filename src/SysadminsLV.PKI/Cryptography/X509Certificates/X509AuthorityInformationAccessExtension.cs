using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Defines Authority Information Access extension (AIA). This extension is used by certificate chaining engine to build
/// certificate chain (retrieve issuer certificate) and/or to check current certificate revocation status by using
/// Online Certificate Status Protocol (OCSP).
/// </summary>
public sealed class X509AuthorityInformationAccessExtension : X509Extension {
    static readonly Oid _oid = new(X509ExtensionOid.AuthorityInformationAccess);
        
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
    public String[] CertificationAuthorityIssuer { get; private set; }
    /// <summary>
    /// Gets Online Certificate Status Protocol service location URLs.
    /// </summary>
    public String[] OnlineCertificateStatusProtocol { get; private set; }

    void m_initialize(IEnumerable<String> authorityIssuer, IEnumerable<String> ocsp, Boolean ocspFirst) {
        Oid = _oid;
        Critical = false;
        var aiaUrlStrings = new List<String>();
        var ocspUrlStrings = new List<String>();
        Byte[] aiaOidBytes = Asn1Utils.EncodeObjectIdentifier(new Oid("1.3.6.1.5.5.7.48.2"));
        Byte[] ocspOidBytes = Asn1Utils.EncodeObjectIdentifier(new Oid("1.3.6.1.5.5.7.48.1"));
        var aiaBytes = new List<Byte>();
        var ocspBytes = new List<Byte>();
        if (authorityIssuer != null) {
            foreach (Uri uri in authorityIssuer.Select(url => new Uri(url))) {
                aiaUrlStrings.Add(uri.AbsoluteUri);
                aiaBytes.AddRange(aiaOidBytes);
                aiaBytes.AddRange(Asn1Utils.Encode(Encoding.ASCII.GetBytes(uri.AbsoluteUri), 134));
                aiaBytes = new List<Byte>(Asn1Utils.Encode(aiaBytes.ToArray(), 48));
            }
            CertificationAuthorityIssuer = aiaUrlStrings.ToArray();
        } else {
            CertificationAuthorityIssuer = Array.Empty<String>();
        }
        if (ocsp != null) {
            foreach (Uri uri in ocsp.Select(url => new Uri(url))) {
                ocspUrlStrings.Add(uri.AbsoluteUri);
                ocspBytes.AddRange(ocspOidBytes);
                ocspBytes.AddRange(Asn1Utils.Encode(Encoding.ASCII.GetBytes(uri.AbsoluteUri), 134));
                ocspBytes = new List<Byte>(Asn1Utils.Encode(ocspBytes.ToArray(), 48));
            }
            OnlineCertificateStatusProtocol = ocspUrlStrings.ToArray();
        } else {
            OnlineCertificateStatusProtocol = Array.Empty<String>();
        }
        List<Byte> rawData;
        if (ocspFirst) {
            ocspBytes.AddRange(aiaBytes.ToArray());
            rawData = ocspBytes;
        } else {
            aiaBytes.AddRange(ocspBytes.ToArray());
            rawData = aiaBytes;
        }
        RawData = Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    void m_decode(Byte[] rawData) {
        var aiaUrls = new List<String>();
        var ocspUrls = new List<String>();
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
        asn.MoveNext();
        do {
            Int32 offset = asn.Offset;
            if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
            asn.MoveNext();
            String oidString = Asn1Utils.DecodeObjectIdentifier(asn.GetTagRawData()).Value;
            asn.MoveNextAndExpectTags(0x86);
            switch (oidString) {
                case "1.3.6.1.5.5.7.48.2": aiaUrls.Add(Encoding.ASCII.GetString(asn.GetPayload())); break;
                case "1.3.6.1.5.5.7.48.1": ocspUrls.Add(Encoding.ASCII.GetString(asn.GetPayload())); break;
            }
            asn.Seek(offset);
        } while (asn.MoveNextSibling());
        CertificationAuthorityIssuer = aiaUrls.ToArray();
        OnlineCertificateStatusProtocol = ocspUrls.ToArray();
    }
}