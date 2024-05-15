using Microsoft.VisualStudio.TestTools.UnitTesting;
using PKI.CertificateTemplates;
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

        [TestMethod]
        public void Test2() {
            var col = new CertificateTemplateCollection();
            var t = CertificateTemplate.FromCommonName("rdp-tlsv3");
            col.Add(t);
            var s = col.Export(CertificateTemplateExportFormat.XCep);
            var col2 = new CertificateTemplateCollection();
            col2.Import(s, CertificateTemplateExportFormat.XCep);
        }
    }
}
