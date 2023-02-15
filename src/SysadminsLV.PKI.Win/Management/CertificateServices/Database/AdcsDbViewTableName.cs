namespace SysadminsLV.PKI.Management.CertificateServices.Database {
    /// <summary>
    /// Contains enumeration of predefined ADCS database view tables.
    /// </summary>
    public enum AdcsDbViewTableName {
        /// <summary>
        /// Sets view table to display entire request table. Request table includes the following view tables:
        /// <list type="bullet">
        ///     <item>Revoked</item>
        ///     <item>Issued</item>
        ///     <item>Pending</item>
        ///     <item>Failed</item>
        /// </list>
        /// </summary>
        Request,
        /// <summary>
        /// Sets view table to display only revoked certificates. This value reflects 'Revoked Certificates' folder
        /// in Certification Authority MMC snap-in.
        /// </summary>
        Revoked,
        /// <summary>
        /// Sets view table to display only issued and non-revoked certificates. This value reflects
        /// 'Issued Certificates' folder in Certification Authority MMC snap-in.
        /// </summary>
        Issued,
        /// <summary>
        /// Sets view table to display only pending requests. This value reflects 'Pending Requests' folder
        /// in Certification Authority MMC snap-in.
        /// </summary>
        Pending,
        /// <summary>
        /// Sets view table to display only failed or explicitly denied by CA manager request. This value reflects
        /// 'Failed Requests' folder in Certification Authority MMC snap-in.
        /// </summary>
        Failed,
        /// <summary>
        /// Sets view table to display extension table. This table contains extensions associated with respective
        /// row in Request table.
        /// </summary>
        Extension,
        /// <summary>
        /// Sets view table to display attribute table. This table contains request attributes associated with
        /// respective row in Request table.
        /// </summary>
        Attribute,
        /// <summary>
        /// Sets view table to display certificate revocation list (CRL) table. This table holds a history of all
        /// ever issued CRLs by particular CA server.
        /// </summary>
        CRL
    }
}