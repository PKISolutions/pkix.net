using System;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace PKI.OCSP {
    /// <summary>
    /// Represents OCSP single response that contains revocation status about particular certificate. Certificate
    /// ID is stored in <see cref="CertID"/> property.
    /// </summary>
    public class OCSPSingleResponse {

        internal OCSPSingleResponse(Asn1Reader rsp) {
            m_initialize(rsp);
        }
        /// <summary>
        /// Gets certificate ID that represents information about the certificate was verified.
        /// </summary>
        public CertID CertId { get; private set; }
        /// <summary>
        /// Gets certificate status. Possible values are: <strong>Good</strong>, <strong>Revoked</strong>, <strong>Unknown</strong>.
        /// </summary>
        public CertificateStatus CertStatus { get; private set; }
        /// <summary>
        /// Gets the time at which the status being indicated is known to be correct.
        /// </summary>
        public DateTime ThisUpdate { get; private set; }
        /// <summary>
        /// Gets the time at or before which newer information will be available about the status of the certificate.
        /// </summary>
        public DateTime? NextUpdate { get; private set; }
        /// <summary>
        /// Gets optional extensions about the status of the certificate in the subject.
        /// </summary>
        public X509ExtensionCollection Extensions { get; } = new();
        /// <summary>
        /// If the certificate in the subject is revoked, OCSP responder may include CRL entry with this certificate.
        /// </summary>
        public X509CRLEntry RevocationInfo { get; private set; }

        void m_initialize(Asn1Reader response) {
            response.MoveNext();
            CertId = new CertID(Asn1Utils.Encode(response.GetPayload(), 48));
            response.MoveNextSibling();
            switch (response.Tag) {
                case 128:
                    CertStatus = CertificateStatus.Good;
                    response.MoveNextSibling();
                    break;
                case 161: 
                    CertStatus = CertificateStatus.Revoked;
                    response.MoveNext();
                    DateTime revokedWhen = Asn1Utils.DecodeGeneralizedTime(response.GetTagRawData());
                    response.MoveNext();
                    Int16 reason = 0;
                    if (response.Tag == 160) {
                        response.MoveNext();
                        reason = response.GetPayload()[0];
                        response.MoveNext();
                    }
                    RevocationInfo = new X509CRLEntry(CertId.SerialNumber, revokedWhen, reason);
                    break;
                case 130:
                    CertStatus = CertificateStatus.Unknown;
                    response.MoveNextSibling();
                    break;
            }
            //response.MoveNextCurrentLevel();
            ThisUpdate = Asn1Utils.DecodeGeneralizedTime(response.GetTagRawData());
            while (response.MoveNextSibling()) {
                switch (response.Tag) {
                    case 160:
                        Asn1Reader asn = new Asn1Reader(response.GetPayload());
                        NextUpdate = Asn1Utils.DecodeGeneralizedTime(asn.GetTagRawData());
                        break;
                    case 161:
                        Extensions.Decode(response.GetPayload());
                        break;
                }
            }
        }
    }
}
