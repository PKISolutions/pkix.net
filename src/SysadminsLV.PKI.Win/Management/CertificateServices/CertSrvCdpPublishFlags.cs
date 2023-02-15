using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Contains flags used by Active Directory Certificate Services to configure certificate revocation list (<strong>CRL</strong>) publication settings.
    /// </summary>
    [Flags]
    public enum CertSrvCdpPublishFlags {
        /// <summary>
        /// No publication flags associated with particular entry. This entry will not be used by certification authority.
        /// </summary>
        None                 = 0,
        /// <summary>
        /// Publish Base CRL object or file to specified location.
        /// </summary>
        PublishToServer      = 1,
        /// <summary>
        /// Include URL in CRL Distribution Points extension of issued certificates.
        /// </summary>
        AddToCertificateCdp  = 2,
        /// <summary>
        /// Include URL in Freshest CRL extension in Base CRL. Is used to locate Delta CRLs.
        /// </summary>
        AddToFreshestCrl     = 4,
        /// <summary>
        /// Include URL in CRL Distribution Points (CDP) extension of Base CRL.
        /// </summary>
        AddToCrlCdp          = 8,
        /// <summary>
        /// Publish Delta CRL object or file to specified location.
        /// </summary>
        PublishDeltaToServer = 64,
        /// <summary>
        /// Publish CRL information to IDP (Issuing Distribution Point) extension.
        /// </summary>
        AddToCrlIdp          = 128
    }
}