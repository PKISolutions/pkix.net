using System;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents a wrapper interface for Microsoft
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-icertadmin2">ICertAdmin2</see> COM interface.
    /// </summary>
    public interface ICertDbAdminD {
        /// <summary>
        /// Approves specified pending certificate request.
        /// </summary>
        /// <param name="requestID">RequestID from Certification Authority database.</param>
        /// <returns>Status of approval operation.</returns>
        AdcsPropCertState ApproveRequest(Int32 requestID);
        /// <summary>
        /// Denies specified pending certificate request.
        /// </summary>
        /// <param name="requestID">RequestID from Certification Authority database.</param>
        void DenyRequest(Int32 requestID);
        /// <summary>
        /// Revokes issued or revoked certificate by its serial number.
        /// </summary>
        /// <param name="serialNumber">A hexadecimal string that represents issued or revoked certificate.</param>
        /// <param name="revocationDate">Optional effective revocation date and time. If not specified, current time is used.</param>
        /// <param name="reason">Optional revocation reason. If not specified, revocation reason is Unspecified.</param>
        void RevokeRequest(String serialNumber, DateTime? revocationDate = null, AdcsCrlReason reason = AdcsCrlReason.Unspecified);
        /// <summary>
        /// Deletes database row from specified database table. Default is request table.
        /// </summary>
        /// <param name="requestID">RequestID or RowID from Certification Authority database.</param>
        /// <param name="table">Specifies the target database table.</param>
        /// <returns>Number of removed rows. Can be 0 or 1.</returns>
        Int32 DeleteDatabaseRow(Int32 requestID, AdcsDbCRTable table = AdcsDbCRTable.Request);
        /// <summary>
        /// Performs database cleanup by removing expired certificate requests. All certificate rows that expired before specified date and time
        /// are deleted.
        /// </summary>
        /// <param name="notAfter">The date and time of certificate expiration.</param>
        /// <returns>Number of removed rows.</returns>
        Int32 DeleteExpiredRequests(DateTime notAfter);
        /// <summary>
        /// Performs database cleanup by removing expired CRLs. All CLR rows that expired before specified date and time
        /// are deleted.
        /// </summary>
        /// <param name="notAfter">The date and time of CRL expiration.</param>
        /// <returns>Number of removed rows.</returns>
        Int32 DeleteExpiredCRLs(DateTime notAfter);
        /// <summary>
        /// Performs database cleanup by removing requests that were last updated before specified date and time.
        /// </summary>
        /// <param name="notAfter">The date and time of last request row update.</param>
        /// <returns>Number of removed rows.</returns>
        Int32 DeleteLastUpdatedRequests(DateTime notAfter);
        /// <summary>
        /// Imports certificate to Certification Authority database.
        /// </summary>
        /// <param name="certificate">A certificate to import.</param>
        /// <exception cref="ArgumentNullException"><strong>certificate</strong> parameter is null.</exception>
        /// <returns>RequestID from request table.</returns>
        Int32 ImportCertificate(X509Certificate2 certificate);
        /// <summary>
        /// Gets the status of certificate by its serial number.
        /// </summary>
        /// <param name="serialNumber">A hexadecimal string that represents a serial number.</param>
        /// <exception cref="ArgumentNullException"><strong>serialNumber</strong> parameter is null.</exception>
        /// <exception cref="ArgumentException"><strong>serialNumber</strong> parameter is not valid serial number string.</exception>
        /// <returns>Status of certificate.</returns>
        AdcsPropCertState GetCertificateStatus(String serialNumber);
    }
}