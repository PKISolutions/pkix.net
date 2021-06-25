using System.Collections.Generic;
using SysadminsLV.PKI;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Management.CertificateServices {
    public class CertSrvCdpUrlCollection : BasicCollection<CertSrvCdpUrlEntry> {
        public CertSrvCdpUrlCollection() { }
        public CertSrvCdpUrlCollection(IEnumerable<CertSrvCdpUrlEntry> collection) : base(collection) { }
    }
}