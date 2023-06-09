using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices;
public class CertSrvCdpUrlCollection : BasicCollection<CertSrvCdpUrlEntry> {
    public CertSrvCdpUrlCollection() { }
    public CertSrvCdpUrlCollection(IEnumerable<CertSrvCdpUrlEntry> collection) : base(collection) { }
}