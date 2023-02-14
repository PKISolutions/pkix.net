using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a single DistributionPoint element of <strong>CRL Distribution Points</strong> certificate
/// extension.
/// </summary>
public class X509DistributionPoint {
    readonly List<Byte> _rawData = new();
    readonly X509AlternativeNameCollection _fullNames = new();
    readonly X509AlternativeNameCollection _crlIssuers = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="X509DistributionPoint"/> class from an array of URLs,
    /// where each URL points to the same CRL location.
    /// </summary>
    /// <param name="uris">One or more URLs to include to the current distribution point.</param>
    public X509DistributionPoint(Uri[] uris) {
        if (uris == null) { throw new ArgumentNullException(nameof(uris)); }
        encode(uris);
    }
    /// <summary>
    /// Initializes a new instance of the <see cref="X509DistributionPoint"/> class from an ASN.1-encoded byte
    /// array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents single distribution point section.</param>
    public X509DistributionPoint(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        decode(rawData);
    }

    /// <summary>
    /// Gets a collection of alternative names associated with the current CRL, where each name provides current
    /// CRL locations.
    /// </summary>
    public X509AlternativeNameCollection FullName => new(_fullNames);
    /// <summary>
    /// Gets a X.500 distinguished name part relative to CRL issuer.
    /// </summary>
    /// <remarks>
    ///		This member is used only when CRL issuer is not the same entity that issued certificate
    ///		in subject.
    /// </remarks>
    public X500DistinguishedName RelativeToIssuerName { get; private set; }
    /// <summary>
    /// Gets the list of reasons covered by CRLs in distribution point.
    /// </summary>
    /// <remarks>If this member is set to zero, then CRLs in this distribution point cover all reasons.</remarks>
    public X509RevocationReasonFlag Reasons { get; private set; }
    /// <summary>
    /// Gets a collection of alternative names to identify CRL issuer.
    /// </summary>
    /// <remarks>
    ///		This member is used only when CRL issuer is not the same entity that issued certificate
    ///		in subject.
    /// </remarks>
    public X509AlternativeNameCollection CRLIssuer => new(_crlIssuers);
    /// <summary>
    /// Gets ASN.1-encoded byte array.
    /// </summary>
    public Byte[] RawData => _rawData.ToArray();

    void decode(Byte[] rawData) {
        Asn1Reader asn = new Asn1Reader(rawData);
        asn.MoveNext();
        if (asn.PayloadLength == 0) { return; }
        do {
            switch (asn.Tag) {
                case 0xA0:
                    Asn1Reader distName = new Asn1Reader(asn.GetPayload());
                    do {
                        switch (distName.Tag) {
                            case 0xA0:
                                // full name
                                _fullNames.Decode(Asn1Utils.Encode(distName.GetPayload(), 48));
                                break;
                            case 0xA1:
                                // relative to issuer name
                                Byte[] relativeName = Asn1Utils.Encode(distName.GetPayload(), 48);
                                RelativeToIssuerName = new X500DistinguishedName(relativeName);
                                break;
                            default:
                                throw new InvalidDataException("The data is invalid");
                        }
                    } while (distName.MoveNextSibling());
                    break;
                case 0xA1:
                    // reasons
                    Asn1BitString bs = new Asn1BitString(asn.GetPayload());
                    if (bs.Value[0] == 0) {
                        Reasons = X509RevocationReasonFlag.Unspecified;
                    } else {
                        Reasons = (X509RevocationReasonFlag) bs.Value[0];
                    }
                    break;
                case 0xA2:
                    // crl issuer
                    _crlIssuers.Decode(Asn1Utils.Encode(asn.GetPayload(), 48));
                    break;
                default:
                    throw new InvalidDataException("The data is invalid.");
            }
        } while (asn.MoveNextSibling());
        _rawData.AddRange(rawData);
    }
    void encode(IEnumerable<Uri> uris) {
        foreach (Uri uri in uris) {
            _fullNames.Add(new X509AlternativeName(X509AlternativeNamesEnum.URL, uri.AbsoluteUri));
        }
        Asn1Reader asn = new Asn1Reader(_fullNames.Encode());
        _rawData.AddRange(Asn1Utils.Encode(asn.GetPayload(), 160));
    }
}