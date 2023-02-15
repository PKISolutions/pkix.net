namespace SysadminsLV.PKI.Management.ActiveDirectory {
    /// <summary>
    /// Contains enumeration of certificate types stored in Active Directory.
    /// </summary>
    public enum DsCertificateType {
        /// <summary>
        /// The certificate is user certificate and stored in <strong>userCertificate</strong> DS attribute.
        /// </summary>
        UserCertificate,
        /// <summary>
        /// The certificate is CA certificate and stored in <strong>cACertificate</strong> DS attribute.
        /// </summary>
        CACertificate,
        /// <summary>
        /// The certificate is cross-certificate and stored in <strong>crossCertificatePair</strong> DS attribute.
        /// </summary>
        CrossCertificate
    }
}