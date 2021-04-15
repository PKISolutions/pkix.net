using System;
using PKI.Management.CertificateServices;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public class CertSrvCdpConfig : CertSrvCdpAiaConfig<CertSrvCdpUrlEntry> {

        public CertSrvCdpConfig(String computerName) : base(computerName, ACTIVE_CRLPUBLICATIONURLS) {
            ConfigManager.SetRootNode(true);
            initialize();
        }

        void initialize() {
            String[] regEntries = ConfigManager.GetMultiStringEntry(ACTIVE_CRLPUBLICATIONURLS);
            foreach (String regEntry in regEntries) {
                Entries.Add(CertSrvCdpUrlEntry.FromRegUri(regEntry));
            }
        }
    }
}