using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Win.Tests.Properties;

namespace SysadminsLV.PKI.Win.Tests.Cryptography;

[TestClass]
public class EccUtils {
    Byte[] bin;
    ECDsa? ecDsa;

    [TestInitialize]
    public void Init() {
        bin = Convert.FromBase64String(Resources.EcDsaPrivKey);
        var ecDsaPrivateKey = new ECDsaPrivateKey(bin);
        ecDsa = ecDsaPrivateKey.GetAsymmetricKey() as ECDsa;

        Assert.IsNotNull(ecDsa);
    }

    [TestMethod]
    public void PemUtilsTest() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.EcDsaPubCert));
        Assert.IsFalse(cert.HasPrivateKey);
        using X509Certificate2 newCert = cert.CopyWithPrivateKey(ecDsa);
        Assert.IsTrue(newCert.HasPrivateKey);
        Assert.IsNull(newCert.PrivateKey);
    }
    [TestMethod]
    public void TestEcDsaCng() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.EcDsaPubCert));
        using CngKey cng = CngKey.Import(bin, CngKeyBlobFormat.Pkcs8PrivateBlob, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        cng.SetProperty(new CngProperty("Export Policy", BitConverter.GetBytes(3), CngPropertyOptions.None));
        using ECDsa ecDsa2 = new ECDsaCng(cng);
        using X509Certificate2 newCert = cert.CopyWithPrivateKey(ecDsa2);
        Assert.IsTrue(newCert.HasPrivateKey);
        Assert.IsNull(newCert.PrivateKey);
        cng.Delete();
    }

    [TestCleanup]
    public void Cleanup() {
        ecDsa?.Dispose();
    }
}