using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Contains flags used by Active Directory Certificate Services to configure CA certificate publication settings.
    /// </summary>
    [Flags]
    public enum CertSrvAiaPublishFlags {
        /// <summary>
        /// No publication flags associated with particular entry. This entry will not be used by certification authority.
        /// </summary>
        None               = 0,
        /// <summary>
        /// Publish CA certificate object or file to specified location.
        /// </summary>
        CertPublish        = 1,
        /// <summary>
        /// Include URL in Authority Information Access (AIA) extension of issued certificates as "Certification Authority Issuer" access method.
        /// </summary>
        AddToCertificateAia = 2,
        /// <summary>
        /// Include URL in Authority Information Access (AIA) extension of issued certificates as "Online Certificate Status Protocol" access method.
        /// </summary>
        AddToCertificateOcsp = 32
    }
}