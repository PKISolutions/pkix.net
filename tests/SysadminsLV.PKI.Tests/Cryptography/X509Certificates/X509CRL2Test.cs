using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;

[TestClass]
public class X509CRL2Test {
    [TestMethod]
    public void TestBaseCRLv1() {
        var crl = new X509CRL2(Convert.FromBase64String(Resources.BaseCRLv1));
        Assert.AreEqual(X509CrlType.BaseCrl, crl.Type);
        Assert.AreEqual(1, crl.Version);
        Assert.AreEqual("CN=VeriSign Class 3 Extended Validation SSL SGC CA, OU=Terms of use at https://www.verisign.com/rpa (c)06, OU=VeriSign Trust Network, O=\"VeriSign, Inc.\", C=US", crl.Issuer);
        Assert.AreEqual(635348016110000000, crl.ThisUpdate.Ticks);
        Assert.IsTrue(crl.NextUpdate.HasValue);
        Assert.AreEqual(635354064110000000, crl.NextUpdate.Value.Ticks);
        Assert.AreEqual(0, crl.Extensions.Count);
        Assert.AreEqual(5697, crl.RevokedCertificates.Count);
        Assert.AreEqual(new Oid("sha1rsa").Value, crl.SignatureAlgorithm.Value);
        Console.WriteLine(crl.ToString(true));
    }
    [TestMethod]
    public void TestBaseCRLv2S2() {
        var crl = new X509CRL2(Convert.FromBase64String(Resources.BaseCRLSHA256v2));
        Assert.AreEqual(X509CrlType.BaseCrl, crl.Type);
        Assert.AreEqual(2, crl.Version);
        Assert.AreEqual("CN=DigiCert SHA2 Extended Validation Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US", crl.Issuer);
        Assert.AreEqual(635347440750000000, crl.ThisUpdate.Ticks);
        Assert.IsTrue(crl.NextUpdate.HasValue);
        Assert.AreEqual(635353488000000000, crl.NextUpdate.Value.Ticks);
        Assert.AreEqual(2, crl.Extensions.Count);
        var aki = crl.Extensions[X509ExtensionOid.AuthorityKeyIdentifier] as X509AuthorityKeyIdentifierExtension;
        Assert.IsNotNull(aki);
        Assert.AreEqual(AuthorityKeyIdentifierType.KeyIdentifier, aki.IncludedComponents);
        Assert.AreEqual("3dd350a5d6a0adeef34a600a65d321d4f8f8d60f", aki.KeyIdentifier);
        var crlnum = crl.Extensions[X509ExtensionOid.CRLNumber] as X509CRLNumberExtension;
        Assert.IsNotNull(crlnum);
        Assert.AreEqual(191, crlnum.CRLNumber);
        Assert.AreEqual(78, crl.RevokedCertificates.Count);
        Assert.AreEqual(new Oid("sha256rsa").Value, crl.SignatureAlgorithm.Value);
        Console.WriteLine(crl.ToString(true));
    }
    [TestMethod]
    public void TestBaseCRLv2() {
        var crl = new X509CRL2(Convert.FromBase64String(Resources.BaseCRLv2));
        Assert.AreEqual(X509CrlType.BaseCrl, crl.Type);
        Assert.AreEqual(2, crl.Version);
        Assert.AreEqual("CN=Adatum Class 1 Issuing SubCA 1, OU=Information Systems, O=Adatum Ltd., C=LV", crl.Issuer);
        Assert.AreEqual(634067647040000000, crl.ThisUpdate.Ticks);
        Assert.IsTrue(crl.NextUpdate.HasValue);
        Assert.AreEqual(634072843040000000, crl.NextUpdate.Value.Ticks);
        Assert.AreEqual(5, crl.Extensions.Count);
        Assert.AreEqual(3, crl.RevokedCertificates.Count);
        Assert.AreEqual(new Oid("sha1rsa").Value, crl.SignatureAlgorithm.Value);
        Assert.IsTrue(crl.HasDelta());
        Console.WriteLine(crl.ToString(true));
    }
    [TestMethod]
    public void TestDeltaCrl() {
        var crl = new X509CRL2(Convert.FromBase64String(Resources.DeltaCRLv2));
        Assert.AreEqual(X509CrlType.DeltaCrl, crl.Type);
        Assert.AreEqual(2, crl.Version);
        Assert.AreEqual("CN=Adatum Class 1 Issuing SubCA 1, OU=Information Systems, O=Adatum Ltd., C=LV", crl.Issuer);
        Assert.AreEqual(634067828560000000, crl.ThisUpdate.Ticks);
        Assert.IsTrue(crl.NextUpdate.HasValue);
        Assert.AreEqual(634068704560000000, crl.NextUpdate.Value.Ticks);
        Assert.AreEqual(5, crl.Extensions.Count);
        Assert.AreEqual(2, crl.RevokedCertificates.Count);
        Assert.AreEqual(new Oid("sha1rsa").Value, crl.SignatureAlgorithm.Value);
        Console.WriteLine(crl.ToString(true));
    }
    [TestMethod]
    public void TestCrlNoSign() {
        var crl = new X509CRL2(Convert.FromBase64String(Resources.NoSignCRL));
        Assert.AreEqual(X509CrlType.BaseCrl, crl.Type);
        Assert.AreEqual(1, crl.Version);
        Assert.AreEqual("CN=contoso-DC2-CA, DC=contoso, DC=com", crl.Issuer);
        Assert.AreEqual(634034778310000000, crl.ThisUpdate.Ticks);
        Assert.IsTrue(crl.NextUpdate.HasValue);
        Assert.AreEqual(635611578310000000, crl.NextUpdate.Value.Ticks);
        Assert.AreEqual(0, crl.Extensions.Count);
        Assert.AreEqual(1, crl.RevokedCertificates.Count);
        Assert.AreEqual(new Oid("sha1nosign").Value, crl.SignatureAlgorithm.Value);
        Console.WriteLine(crl.ToString(true));
    }
    [TestMethod]
    public void TestMinimalCRL() {
        var crl = new X509CRL2(Convert.FromBase64String(Resources.MinimalCRL));
        Console.WriteLine(crl.ToString(true));
    }
    [TestMethod]
    public void TestX509CRL2GetExtensions() {
        var basev2 = new X509CRL2(Convert.FromBase64String(Resources.BaseCRLv2));
        Assert.AreNotEqual(null, basev2.Extensions);
        Assert.AreEqual(5, basev2.Extensions.Count);

        // Next CRL Publish
        Assert.AreNotEqual(null, basev2.Extensions[X509ExtensionOid.NextCRLPublish]);
        Assert.AreNotEqual(null, basev2.GetNextPublish());
        Assert.AreEqual("18.04.2010 14:21:44", ((DateTime)basev2.GetNextPublish()).ToString("dd.MM.yyyy HH:mm:ss"));

        // CRL number
        Assert.AreNotEqual(null, basev2.Extensions[X509ExtensionOid.CRLNumber]);
        var crlNumber = (X509CRLNumberExtension)basev2.Extensions[X509ExtensionOid.CRLNumber];
        Assert.IsNotNull(crlNumber);
        Assert.AreEqual(28, crlNumber.CRLNumber);
    }
}