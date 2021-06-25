using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices {
    public class CertSrvAiaUrlCollection : BasicCollection<CertSrvAiaUrlEntry> {
        public CertSrvAiaUrlCollection() { }
        public CertSrvAiaUrlCollection(IEnumerable<CertSrvAiaUrlEntry> collection) : base(collection) { }
    }
}