using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Win.Tests.Properties;

namespace SysadminsLV.PKI.Win.Tests.Cryptography.X509Certificates; 
[TestClass]
public class X509Certificate2PropertiesTest {
    readonly X509Certificate2 _cert;

    public X509Certificate2PropertiesTest() {
        var certs = new X509Certificate2Collection();
        certs.Import(Convert.FromBase64String(Resources.CertSerializedStore));
        _cert = certs[0];
    }

    [TestMethod]
    public void GetCertPropertyList() {
        Console.WriteLine(_cert.IssuerName.FormatReverse(false));
        Console.WriteLine(_cert.IssuerName.FormatReverse(true));
        Console.WriteLine(_cert.Extensions.Format());
        Console.WriteLine(_cert.Format());
        X509CertificatePropertyType[] list = _cert.GetCertificateContextPropertyList();
        X509CertificateContextPropertyCollection props = _cert.GetCertificateContextProperties();
    }

    [TestMethod]
    public void GetCertificateProperties() {
        var list = _cert.GetCertificateContextPropertyList();
        var prop = _cert.GetCertificateContextProperty(X509CertificatePropertyType.ProviderInfo);
        var provInfo = (KeyProviderInfo)prop.PropertyValue;
        Assert.AreEqual("{0B71DF66-44C6-4FC7-8496-4C964A68DCBD}", provInfo.ContainerName);
        Assert.AreEqual(0, provInfo.Flags);
        Assert.AreEqual(X509KeySpecFlags.AT_NONE, provInfo.KeySpec);
        Assert.AreEqual("Microsoft Software Key Storage Provider", provInfo.ProviderName);
        Assert.AreEqual(0, provInfo.ProviderType);
    }
}
