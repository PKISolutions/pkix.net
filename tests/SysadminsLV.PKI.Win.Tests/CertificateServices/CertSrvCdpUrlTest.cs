using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Test.CertificateServices {
    [TestClass]
    public class CertSrvCdpUrlTest {
        CertSrvCdpConfig config1, config2;

        [TestInitialize]
        public void Initialize() {
            config1 = new CertSrvCdpConfig("hq-s-ipica1");
            config2 = new CertSrvCdpConfig("hq-s-epica2");
        }

        [TestMethod]
        public void TestConfig1_1() {
            Assert.AreEqual(3, config1.Count);
            Assert.AreEqual(UrlProtocolScheme.Local, config1[0].UrlScheme);
            Assert.AreEqual(@"65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl", config1[0].GetRegUri());
            Assert.AreEqual(@"C:\Windows\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl", config1[0].Uri);
            Assert.IsTrue(config1[0].PublishToServer);
            Assert.IsTrue(config1[0].PublishDeltaToServer);
            Assert.IsFalse(config1[0].AddToCertificateCdp);
            Assert.IsFalse(config1[0].AddToFreshestCrl);
            Assert.IsFalse(config1[0].AddToCrlCdp);
            Assert.IsFalse(config1[0].AddToCrlIdp);
        }
        [TestMethod]
        public void TestConfig1_2() {
            Assert.AreEqual(UrlProtocolScheme.UNC, config1[1].UrlScheme);
            Assert.AreEqual(@"65:\\sysadmins.lv\shares\certdata\pica-1%8%9.crl", config1[1].GetRegUri());
            Assert.AreEqual(@"\\sysadmins.lv\shares\certdata\pica-1<CRLNameSuffix><DeltaCRLAllowed>.crl", config1[1].Uri);
            Assert.IsTrue(config1[1].PublishToServer);
            Assert.IsTrue(config1[1].PublishDeltaToServer);
            Assert.IsFalse(config1[1].AddToCertificateCdp);
            Assert.IsFalse(config1[1].AddToFreshestCrl);
            Assert.IsFalse(config1[1].AddToCrlCdp);
            Assert.IsFalse(config1[1].AddToCrlIdp);
        }
        [TestMethod]
        public void TestConfig1_3() {
            Assert.AreEqual(3, config1.Count);
            Assert.AreEqual(UrlProtocolScheme.HTTP, config1[2].UrlScheme);
            Assert.AreEqual("6:http://cdp.sysadmins.lv/repository/pica-1%8%9.crl", config1[2].GetRegUri());
            Assert.AreEqual("http://cdp.sysadmins.lv/repository/pica-1<CRLNameSuffix><DeltaCRLAllowed>.crl", config1[2].Uri);
            Assert.IsFalse(config1[2].PublishToServer);
            Assert.IsFalse(config1[2].PublishDeltaToServer);
            Assert.IsTrue(config1[2].AddToCertificateCdp);
            Assert.IsTrue(config1[2].AddToFreshestCrl);
            Assert.IsFalse(config1[2].AddToCrlCdp);
            Assert.IsFalse(config1[2].AddToCrlIdp);
        }

        [TestMethod]
        public void TestConfig2_1() {
            Assert.AreEqual(UrlProtocolScheme.Local, config2[0].UrlScheme);
            Assert.AreEqual(@"65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl", config2[0].GetRegUri());
            Assert.AreEqual(@"C:\Windows\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl", config2[0].Uri);
            Assert.IsTrue(config2[0].PublishToServer);
            Assert.IsTrue(config2[0].PublishDeltaToServer);
            Assert.IsFalse(config2[0].AddToCertificateCdp);
            Assert.IsFalse(config2[0].AddToFreshestCrl);
            Assert.IsFalse(config2[0].AddToCrlCdp);
            Assert.IsFalse(config2[0].AddToCrlIdp);
        }
        [TestMethod]
        public void TestConfig2_2() {
            Assert.AreEqual(UrlProtocolScheme.UNC, config2[1].UrlScheme);
            Assert.AreEqual(@"65:\\sysadmins.lv\shares\certdata\evca-2%8%9.crl", config2[1].GetRegUri());
            Assert.AreEqual(@"\\sysadmins.lv\shares\certdata\evca-2<CRLNameSuffix><DeltaCRLAllowed>.crl", config2[1].Uri);
            Assert.IsTrue(config2[1].PublishToServer);
            Assert.IsTrue(config2[1].PublishDeltaToServer);
            Assert.IsFalse(config2[1].AddToCertificateCdp);
            Assert.IsFalse(config2[1].AddToFreshestCrl);
            Assert.IsFalse(config2[1].AddToCrlCdp);
            Assert.IsFalse(config2[1].AddToCrlIdp);
        }
        [TestMethod]
        public void TestConfig2_3() {
            Assert.AreEqual(UrlProtocolScheme.HTTP, config2[2].UrlScheme);
            Assert.AreEqual("134:http://www.sysadmins.lv/pki/evca-2%8%9.crl", config2[2].GetRegUri());
            Assert.AreEqual("http://www.sysadmins.lv/pki/evca-2<CRLNameSuffix><DeltaCRLAllowed>.crl", config2[2].Uri);
            Assert.IsFalse(config2[2].PublishToServer);
            Assert.IsFalse(config2[2].PublishDeltaToServer);
            Assert.IsTrue(config2[2].AddToCertificateCdp);
            Assert.IsTrue(config2[2].AddToFreshestCrl);
            Assert.IsFalse(config2[2].AddToCrlCdp);
            Assert.IsTrue(config2[2].AddToCrlIdp);
        }
    }
}