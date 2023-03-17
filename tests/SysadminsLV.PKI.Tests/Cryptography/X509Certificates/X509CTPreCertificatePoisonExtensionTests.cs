using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;

[TestClass]
public class X509CTPreCertificatePoisonExtensionTests {
    [TestMethod]
    public void TestDefault() {
        String base64Value = "BQA=";

        var ext = new X509CTPreCertificatePoisonExtension();
        Assert.AreEqual(X509ExtensionOid.CTPrecertificatePoison, ext.Oid.Value);
        Assert.AreEqual("CT Precertificate Poison", ext.Oid.FriendlyName);
        Assert.IsTrue(ext.Critical);
        Assert.AreEqual(base64Value, Convert.ToBase64String(ext.Value));
        Assert.AreEqual(base64Value, Convert.ToBase64String(ext.RawData));
        Assert.IsTrue(ext.Format(true).EndsWith("\r\n"));
        Assert.IsFalse(ext.Format(false).EndsWith("\r\n"));
    }
}
