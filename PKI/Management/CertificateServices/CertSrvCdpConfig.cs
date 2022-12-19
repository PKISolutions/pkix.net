using System;
using PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents an ADCS Certification Authority CRL Distribution Points (CDP) extension configuration. Use this class to manage CDP
    /// extension of CA server.
    /// </summary>
    public class CertSrvCdpConfig : CertSrvCdpAiaConfig<CertSrvCdpUrlEntry> {
        /// <summary>
        /// Initializes a new instance of <strong>CertSrvCdpConfig</strong> class from CA host name.
        /// </summary>
        /// <param name="computerName">CA server host name.</param>
        public CertSrvCdpConfig(String computerName) : base(computerName, ACTIVE_CRLPUBLICATIONURLS) {
            ConfigManager.SetRootNode(true);
            initialize();
        }

        /// <summary>
        /// Gets a read-only collection of CRL Distribution Point configuration URLs.
        /// </summary>
        public CertSrvCdpUrlCollection Entries => new(InternalEntries);

        void initialize() {
            String[] regEntries = ConfigManager.GetMultiStringEntry(ACTIVE_CRLPUBLICATIONURLS);
            foreach (String regEntry in regEntries) {
                InternalEntries.Add(CertSrvCdpUrlEntry.FromRegUri(regEntry));
            }
        }
    }
}