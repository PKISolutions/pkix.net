using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509SANExtensionTests {
    [TestMethod]
    public void TestSANFromRawData() {
        var asn = new AsnEncodedData(Convert.FromBase64String(Resources.SAN));
        var e = new X509SubjectAlternativeNamesExtension(asn, false);
        var a = new X509AlternativeName(X509AlternativeNamesEnum.DnsName, "www.contoso.com");
        var b = new X509AlternativeName(a.RawData);
        Assert.AreEqual(a.Value, b.Value);
    }
    [TestMethod]
    public void TestSANFromNames() {
        var names = new X509AlternativeNameCollection {
            new(X509AlternativeNamesEnum.DirectoryName,"CN=main, OU=test, DC=com"),
            new(X509AlternativeNamesEnum.DnsName,"www.contoso.com"),
            new(X509AlternativeNamesEnum.Rfc822Name,"email@company.com"),
            new(X509AlternativeNamesEnum.IpAddress,"192.168.2.56"),
            new(X509AlternativeNamesEnum.IpAddress,"2001:0db8:85a3:08d3:1319:8a2e:0370:7348"),
            new(X509AlternativeNamesEnum.RegisteredId,"1.3.6.1.4.1.311.25.1"),
            new(X509AlternativeNamesEnum.URL,"https://verisign.com"),
            new(X509AlternativeNamesEnum.UserPrincipalName,"admin@contoso.com"),
            new(X509AlternativeNamesEnum.OtherName,new Byte[]{207,71,151,244,189,243,76,119,142,5,17,132,194,27,251,121},new Oid("1.3.56.7.45"))
        };
        names[0].Format(false);
        var e = new X509SubjectAlternativeNamesExtension(names, false);
        var asn = new AsnEncodedData(Convert.FromBase64String(Resources.SAN));
        var e2 = new X509SubjectAlternativeNamesExtension(asn, false);
        for (Int32 i = 0; i < names.Count; i++) {
            if (e.AlternativeNames[i].OID == null) {
                Assert.IsNull(e2.AlternativeNames[i].OID);
            }
            if (e.AlternativeNames[i].OID != null) {
                Assert.IsNotNull(e2.AlternativeNames[i].OID);
                Assert.AreEqual(e.AlternativeNames[i].OID.Value, e2.AlternativeNames[i].OID.Value);
            }
            Assert.AreEqual(e.AlternativeNames[i].Type, e2.AlternativeNames[i].Type);
            Assert.AreEqual(e.AlternativeNames[i].Value, e2.AlternativeNames[i].Value);
        }
        //Assert.IsTrue(e.RawData.SequenceEqual(e2.RawData));
    }
}
