using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Management.ActiveDirectory;

namespace SysadminsLV.PKI.Win.Tests.CertificateTemplates {
    [TestClass]
    public class CertTmplTests {
        [TestMethod]
        public void Test() {
            foreach (IAdcsCertificateTemplate t in DsCertificateTemplate.GetAll()) {
                // need to figure out how to test this.
            }
        }
    }
}
