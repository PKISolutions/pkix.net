using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509AltNameTests {
    [TestMethod]
    public void TestAltNameEncode() {
        var name = new X509AlternativeName(X509AlternativeNamesEnum.IpAddress, "192.168.5.0");
        Assert.AreEqual("192.168.5.0", name.Value);
        name = new X509AlternativeName(X509AlternativeNamesEnum.IpAddress, "192.168.5.0/24");
        Assert.AreEqual("192.168.5.0/24", name.Value);
        name = new X509AlternativeName(X509AlternativeNamesEnum.IpAddress, "0.0.0.0/0");
        Assert.AreEqual("0.0.0.0/0", name.Value);
    }
    [TestMethod]
    public void TestEmptyAltName() {
        var name = new X509AlternativeName(X509AlternativeNamesEnum.DnsName, null);
    }
}
