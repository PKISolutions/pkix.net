using System.Text;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents X.509 Archive Cutoff extension which is first defined in <see href="http://tools.ietf.org/html/rfc2560">RFC2560</see>.
    /// </summary>
    /// <remarks>
    /// An OCSP responder MAY choose to retain revocation information beyond a certificate's expiration. 
    /// The date obtained by subtracting this retention interval value from the producedAt time in a response is
    /// defined as the certificate's "archive cutoff" date. OCSP-enabled applications would use an OCSP
    /// archive cutoff date to contribute to a proof that a digital signature was (or was not) reliable on
    /// the date it was produced even if the certificate needed to validate the signature has long since expired.
    /// <para>
    /// To illustrate, if a server is operated with a 7-year retention interval policy and status was produced
    /// at time t1 then the value for ArchiveCutoff in the response would be (t1 - 7 years).
    /// </para>
    /// </remarks>
    public class X509ArchiveCutoffExtension : X509Extension {
        readonly Oid _oid = new(X509ExtensionOid.ArchiveCutoff, "Archive Cutoff");
        /// <summary>
        /// Initializes a new instance of the <strong>X509ArchiveCutoffExtension</strong> class.
        /// </summary>
        public X509ArchiveCutoffExtension() {
            Oid = _oid;
        }
        /// <summary>
        /// Initializes a new instance of the <strong>X509ArchiveCutoffExtension</strong> class using an
        /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="value">The encoded data to use to create the extension.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <exception cref="ArgumentException">
        /// The data in the <strong>value</strong> parameter is not valid extension value.
        /// </exception>
        public X509ArchiveCutoffExtension(AsnEncodedData value, Boolean critical)
            : base(new Oid(X509ExtensionOid.OcspCRLReference, "Archive Cutoff"), value.RawData, critical) {
            m_decode(value.RawData);
        }
        /// <summary>
        /// Initializes a new instance of the <strong>X509ArchiveCutoffExtension</strong> class using a cutoff date.
        /// </summary>
        /// <param name="cutoffDate"></param>
        public X509ArchiveCutoffExtension(DateTime cutoffDate) {
            Oid = _oid;
            CutoffDate = cutoffDate;
            m_initialize(cutoffDate);
        }

        /// <summary>
        /// Gets a cutoff date and time.
        /// </summary>
        public DateTime CutoffDate { get; private set; }

        void m_initialize(DateTime cutoff) {
            RawData = Asn1Utils.EncodeGeneralizedTime(cutoff);
        }
        void m_decode(Byte[] rawData) {
            CutoffDate = Asn1Utils.DecodeGeneralizedTime(rawData);
        }

        /// <summary>
        /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
        /// </summary>
        /// <param name="multiLine"><strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>.</param>
        /// <returns>A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data.</returns>
        public override String Format(Boolean multiLine) {
            StringBuilder SB = new StringBuilder();
            SB.Append("Cutoff date: ");
            if (multiLine) { SB.Append(Environment.NewLine + "     "); }
            SB.Append(CutoffDate);
            return SB.ToString();
        }
    }
}
