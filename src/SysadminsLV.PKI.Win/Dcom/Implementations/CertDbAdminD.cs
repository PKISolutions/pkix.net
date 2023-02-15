using System;
using System.Security.Cryptography.X509Certificates;
using CERTADMINLib;
using PKI.Utils;

namespace SysadminsLV.PKI.Dcom.Implementations {
    /// <summary>
    /// Represents a managed implementation of <see cref="ICertDbAdminD"/> interface that includes Certification Authority database management
    /// operations.
    /// </summary>
    public class CertDbAdminD : ICertDbAdminD {
        readonly String _configString;

        /// <summary>
        /// Initializes a new instance of <strong>CertDbAdminD</strong> from a Certification Authority configuration string.
        /// </summary>
        /// <param name="configString">Certification Authority configuration string.</param>
        public CertDbAdminD(String configString) {
            _configString = configString;
        }

        /// <inheritdoc />
        public AdcsPropCertState ApproveRequest(Int32 requestID) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return (AdcsPropCertState)certAdmin.ResubmitRequest(_configString, requestID);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public void DenyRequest(Int32 requestID) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                certAdmin.DenyRequest(_configString, requestID);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public void RevokeRequest(String serialNumber, DateTime? revocationDate = null, AdcsCrlReason reason = AdcsCrlReason.Unspecified) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                certAdmin.RevokeCertificate(_configString, serialNumber, (Int32)reason, revocationDate ?? DateTime.UtcNow);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public Int32 DeleteDatabaseRow(Int32 requestID, AdcsDbCRTable table = AdcsDbCRTable.Request) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return certAdmin.DeleteRow(_configString, 0, new DateTime(), (Int32)table, requestID);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public Int32 DeleteExpiredRequests(DateTime notAfter) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return certAdmin.DeleteRow(_configString, (Int32)BulkRowRemovalOption.Expired, notAfter, (Int32)AdcsDbCRTable.Request, 0);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public Int32 DeleteExpiredCRLs(DateTime notAfter) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return certAdmin.DeleteRow(_configString, (Int32)BulkRowRemovalOption.Expired, notAfter, (Int32)AdcsDbCRTable.CRL, 0);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public Int32 DeleteLastUpdatedRequests(DateTime notAfter) {
            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return certAdmin.DeleteRow(_configString, (Int32)BulkRowRemovalOption.LastChanged, notAfter, (Int32)AdcsDbCRTable.Request, 0);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public Int32 ImportCertificate(X509Certificate2 certificate) {
            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return certAdmin.ImportCertificate(
                    _configString,
                    CryptographyUtils.EncodeDerString(certificate.RawData),
                    (Int32) ImportForeignOption.AllowForeign);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
        /// <inheritdoc />
        public AdcsPropCertState GetCertificateStatus(String serialNumber) {
            if (serialNumber == null) {
                throw new ArgumentNullException(nameof(serialNumber));
            }
            if (String.IsNullOrWhiteSpace(serialNumber)) {
                throw new ArgumentException("'serialNumber' parameter cannot be empty string");
            }

            ICertAdmin2 certAdmin = new CCertAdminClass();
            try {
                return (AdcsPropCertState)certAdmin.IsValidCertificate(_configString, serialNumber);
            } finally {
                CryptographyUtils.ReleaseCom(certAdmin);
            }
        }
    }
}