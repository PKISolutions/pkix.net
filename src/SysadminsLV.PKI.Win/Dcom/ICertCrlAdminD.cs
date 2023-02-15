using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents a wrapper interface for Microsoft
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-icertadmin2">ICertAdmin2</see> COM interface.
    /// </summary>
    public interface ICertCrlAdminD {
        /// <summary>
        /// Publishes a new base CRL.
        /// </summary>
        /// <param name="nexUpdate">
        /// Optional value for <strong>NextPublish</strong> CRL field. If parameter is null, Certification Authority will automatically calculate
        /// the <strong>NextUpdate</strong> field.
        /// </param>
        void PublishBaseCrl(DateTime? nexUpdate = null);
        /// <summary>
        /// Publishes a new Delta CRL.
        /// </summary>
        /// <param name="nexUpdate">
        /// Optional value for <strong>NextPublish</strong> CRL field. If parameter is null, Certification Authority will automatically calculate
        /// the <strong>NextUpdate</strong> field.
        /// </param>
        void PublishDeltaCrl(DateTime? nexUpdate = null);
        /// <summary>
        /// Publishes a new base and (if configured) delta CRL.
        /// </summary>
        /// <param name="nexUpdate">
        /// Optional value for <strong>NextPublish</strong> CRL field. If parameter is null, Certification Authority will automatically calculate
        /// the <strong>NextUpdate</strong> field.
        /// </param>
        void PublishAllCrl(DateTime? nexUpdate = null);
        /// <summary>
        /// The most recent base and (if configured) delta CRL to distribution points. New CRL is not generated.
        /// </summary>
        /// <remarks>
        /// The CA will not republish a CRL to a CRL distribution point if the CRL at the distribution point is already the most recent CRL.
        /// </remarks>
        void RepublishDistributionPoints();
    }
}