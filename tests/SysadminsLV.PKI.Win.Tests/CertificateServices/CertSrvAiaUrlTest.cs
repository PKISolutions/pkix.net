using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Test.CertificateServices {
    [TestClass]
    public class CertSrvAiaUrlTest {
        CertSrvAiaConfig config1, config2;

        [TestInitialize]
        public void Initialize() {
            config1 = new CertSrvAiaConfig("hq-s-ipica1");
            config2 = new CertSrvAiaConfig("hq-s-epica2");
        }

        [TestMethod]
        public void TestConfig1_1() {
            Assert.AreEqual(3, config1.Count);

            const Int32 index = 0;
            Assert.AreEqual(UrlProtocolScheme.Local, config1[index].UrlScheme);
            Assert.AreEqual(@"1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt", config1[index].GetRegUri());
            Assert.AreEqual(@"C:\Windows\system32\CertSrv\CertEnroll\<ServerDNSName>_<CaName><CertificateName>.crt", config1[index].Uri);
            Assert.IsTrue(config1[index].ServerPublish);
            Assert.IsFalse(config1[index].AddToCertificateAia);
            Assert.IsFalse(config1[index].AddToCertificateOcsp);
        }
        [TestMethod]
        public void TestConfig1_2() {
            const Int32 index = 1;
            Assert.AreEqual(UrlProtocolScheme.HTTP, config1[index].UrlScheme);
            Assert.AreEqual("32:http://ocsp.sysadmins.lv", config1[index].GetRegUri());
            Assert.AreEqual("http://ocsp.sysadmins.lv", config1[index].Uri);
            Assert.IsFalse(config1[index].ServerPublish);
            Assert.IsFalse(config1[index].AddToCertificateAia);
            Assert.IsTrue(config1[index].AddToCertificateOcsp);
        }
        [TestMethod]
        public void TestConfig1_3() {
            const Int32 index = 2;
            Assert.AreEqual(3, config1.Count);
            Assert.AreEqual(UrlProtocolScheme.HTTP, config1[index].UrlScheme);
            Assert.AreEqual("2:http://cdp.sysadmins.lv/repository/pica-1%4.crt", config1[index].GetRegUri());
            Assert.AreEqual("http://cdp.sysadmins.lv/repository/pica-1<CertificateName>.crt", config1[index].Uri);
            Assert.IsFalse(config1[index].ServerPublish);
            Assert.IsTrue(config1[index].AddToCertificateAia);
            Assert.IsFalse(config1[index].AddToCertificateOcsp);
        }

        [TestMethod]
        public void TestConfig2_1() {
            Assert.AreEqual(3, config2.Count);

            const Int32 index = 0;
            Assert.AreEqual(UrlProtocolScheme.Local, config2[index].UrlScheme);
            Assert.AreEqual(@"1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt", config2[index].GetRegUri());
            Assert.AreEqual(@"C:\Windows\system32\CertSrv\CertEnroll\<ServerDNSName>_<CaName><CertificateName>.crt", config2[index].Uri);
            Assert.IsTrue(config2[index].ServerPublish);
            Assert.IsFalse(config2[index].AddToCertificateAia);
            Assert.IsFalse(config2[index].AddToCertificateOcsp);
        }
        [TestMethod]
        public void TestConfig2_2() {
            const Int32 index = 1;
            Assert.AreEqual(UrlProtocolScheme.HTTP, config2[index].UrlScheme);
            Assert.AreEqual("2:http://www.sysadmins.lv/pki/evca-2%4.crt", config2[index].GetRegUri());
            Assert.AreEqual("http://www.sysadmins.lv/pki/evca-2<CertificateName>.crt", config2[index].Uri);
            Assert.IsFalse(config2[index].ServerPublish);
            Assert.IsTrue(config2[index].AddToCertificateAia);
            Assert.IsFalse(config2[index].AddToCertificateOcsp);
        }
        [TestMethod]
        public void TestConfig2_3() {
            const Int32 index = 2;
            Assert.AreEqual(UrlProtocolScheme.HTTP, config2[index].UrlScheme);
            Assert.AreEqual("32:http://ocsp.sysadmins.lv", config2[index].GetRegUri());
            Assert.AreEqual("http://ocsp.sysadmins.lv", config2[index].Uri);
            Assert.IsFalse(config2[index].ServerPublish);
            Assert.IsFalse(config2[index].AddToCertificateAia);
            Assert.IsTrue(config2[index].AddToCertificateOcsp);
        }
    }
}
