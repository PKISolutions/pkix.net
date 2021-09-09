using System.IO;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a single DistributionPoint element of <strong>CRL Distribution Points</strong> certificate
    /// extension.
    /// </summary>
    public class X509DistributionPoint {

        /// <summary>
        /// Initializes a new instance of the <see cref="X509DistributionPoint"/> class from an array of URLs,
        /// where each URL points to the same CRL location.
        /// </summary>
        /// <param name="uris">One or more URLs to include to the current distribution point.</param>
        public X509DistributionPoint(Uri[] uris) {
            if (uris == null) { throw new ArgumentNullException(nameof(uris)); }
            m_encode(uris);
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509DistributionPoint"/> class from an ASN.1-encoded byte
        /// array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array that represents single distribution point section.</param>
        public X509DistributionPoint(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_decode(rawData);
        }

        /// <summary>
        /// Gets a collection of alternative names associated with the current CRL, where each name provides current
        /// CRL locations.
        /// </summary>
        public X509AlternativeNameCollection FullName { get; private set; }
        /// <summary>
        /// Gets a X.500 distinguished name part relateive to CRL issuer.
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
        public X509RevocationReasons Reasons { get; private set; }
        /// <summary>
        /// Gets a collection of alternative names to identify CRL issuer.
        /// </summary>
        /// <remarks>
        ///		This member is used only when CRL issuer is not the same entity that issued certificate
        ///		in subject.
        /// </remarks>
        public X509AlternativeNameCollection CRLIssuer { get; private set; }
        /// <summary>
        /// Gets ASN.1-encoded byte array.
        /// </summary>
        public Byte[] RawData { get; private set; }

        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            asn.MoveNext();
            if (asn.PayloadLength == 0) { return; }
            do {
                Byte[] altNames;
                switch (asn.Tag) {
                    case 0xA0:
                        Asn1Reader distName = new Asn1Reader(asn.GetPayload());
                        do {
                            switch (distName.Tag) {
                                case 0xA0:
                                    // full name
                                    altNames = Asn1Utils.Encode(distName.GetPayload(), 48);
                                    FullName = new X509AlternativeNameCollection();
                                    FullName.Decode(altNames);
                                    break;
                                case 0xA1:
                                    // relative to issuer name
                                    Byte[] relativeName = Asn1Utils.Encode(distName.GetPayload(), 48);
                                    RelativeToIssuerName = new X500DistinguishedName(relativeName);
                                    break;
                                default:
                                    throw new InvalidDataException("The data is invalid");
                            }
                        } while (distName.MoveNextCurrentLevel());
                        break;
                    case 0xA1:
                        // reasons
                        Asn1BitString bs = new Asn1BitString(asn.GetPayload());
                        if (bs.Value[0] == 0) {
                            Reasons = X509RevocationReasons.Unspecified;
                            break;
                        }
                        Byte mask = 1;
                        do {
                            if ((bs.Value[0] & mask) > 0) {
                                switch (mask) {
                                    case 1: Reasons += (Int32)X509RevocationReasons.AACompromise; break;
                                    case 2: Reasons += (Int32)X509RevocationReasons.PrivilegeWithdrawn; break;
                                    case 4: Reasons += (Int32)X509RevocationReasons.CertificateHold; break;
                                    case 8: Reasons += (Int32)X509RevocationReasons.CeaseOfOperation; break;
                                    case 16: Reasons += (Int32)X509RevocationReasons.Superseded; break;
                                    case 32: Reasons += (Int32)X509RevocationReasons.ChangeOfAffiliation; break;
                                    case 64: Reasons += (Int32)X509RevocationReasons.CACompromise; break;
                                    case 128: Reasons += (Int32)X509RevocationReasons.KeyCompromise; break;
                                }
                            }
                            mask <<= 1;
                        } while (mask != 128);
                        break;
                    case 0xA2:
                        // crl issuer
                        altNames = Asn1Utils.Encode(asn.GetPayload(), 48);
                        CRLIssuer = new X509AlternativeNameCollection();
                        CRLIssuer.Decode(altNames);
                        break;
                    default:
                        throw new InvalidDataException("The data is invalid.");
                }
            } while (asn.MoveNextCurrentLevel());
            RawData = rawData;
        }
        void m_encode(Uri[] uris) {
            X509AlternativeNameCollection altnames = new X509AlternativeNameCollection();
            foreach (Uri uri in uris) {
                altnames.Add(new X509AlternativeName(X509AlternativeNamesEnum.URL, uri.AbsoluteUri));
            }
            FullName = altnames;
            Asn1Reader asn = new Asn1Reader(altnames.Encode());
            RawData = Asn1Utils.Encode(asn.GetPayload(), 160);
        }
    }
}
