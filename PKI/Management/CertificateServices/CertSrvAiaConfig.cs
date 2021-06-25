using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public sealed class CertSrvAiaConfig : CertSrvCdpAiaConfig<CertSrvAiaUrlEntry> {
        public CertSrvAiaConfig(String computerName) : base(computerName, ACTIVE_CACERTPUBLICATIONURLS) {
            initialize();
        }

        /// <summary>
        /// Gets a read-only collection of Authority Information Access config URLs.
        /// </summary>
        public CertSrvAiaUrlCollection Entries => new CertSrvAiaUrlCollection(InternalEntries);

        void initialize() {
            String[] regEntries = ConfigManager.GetMultiStringEntry(ACTIVE_CACERTPUBLICATIONURLS);
            foreach (String regEntry in regEntries) {
                InternalEntries.Add(CertSrvAiaUrlEntry.FromRegUri(regEntry));
            }
        }
    }
}
