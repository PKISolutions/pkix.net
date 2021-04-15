using System;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Management.CertificateServices {
    public sealed class CertSrvAiaConfig : CertSrvCdpAiaConfig<CertSrvAiaUrlEntry> {
        public CertSrvAiaConfig(String computerName) : base(computerName, ACTIVE_CACERTPUBLICATIONURLS) {
            initialize();
        }

        void initialize() {
            String[] regEntries = ConfigManager.GetMultiStringEntry(ACTIVE_CACERTPUBLICATIONURLS);
            foreach (String regEntry in regEntries) {
                Entries.Add(CertSrvAiaUrlEntry.FromRegUri(regEntry));
            }
        }
    }
}
