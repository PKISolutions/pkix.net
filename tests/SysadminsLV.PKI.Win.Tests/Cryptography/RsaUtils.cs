using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Win.Tests.Properties;

namespace SysadminsLV.PKI.Win.Tests.Cryptography;
[TestClass]
public class RsaUtils {
    const String Capi1Prov = "Microsoft Enhanced RSA and AES Cryptographic Provider";
    const String Capi2Prov = "Microsoft Software Key Storage Provider";

    Byte[] bin;
    RSA? rsa;

    [TestInitialize]
    public void Init() {
        bin = Convert.FromBase64String(Resources.RsaPrivKey);
        var rsaPrivateKey = new RsaPrivateKey(bin);
        rsa = rsaPrivateKey.GetAsymmetricKey() as RSA;
        Assert.IsNotNull(rsa);

        var bin2 = rsaPrivateKey.Export(KeyPkcsFormat.Pkcs8);
        Assert.IsTrue(bin.SequenceEqual(bin2));
    }

    [TestMethod]
    public void PemUtilsTest() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.RsaPubCert));
        Assert.IsFalse(cert.HasPrivateKey);
        using X509Certificate2 newCert = cert.CopyWithPrivateKey(rsa);
        Assert.IsTrue(newCert.HasPrivateKey);
        Assert.IsNull(newCert.PrivateKey);
    }
    [TestMethod]
    public void TestRsaCsp() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.RsaPubCert));
        using CngKey cng = CngKey.Import(bin, CngKeyBlobFormat.Pkcs8PrivateBlob, new CngProvider(Capi1Prov));
        cng.SetProperty(new CngProperty("Export Policy", BitConverter.GetBytes(3), CngPropertyOptions.None));
        using RSA rsa2 = new RSACng(cng);
        using X509Certificate2 newCert = cert.CopyWithPrivateKey(rsa2);
        Assert.IsTrue(newCert.HasPrivateKey);
        Assert.IsNull(newCert.PrivateKey);
        cng.Delete();
    }
    [TestMethod]
    public void TestRsaCng() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.RsaPubCert));
        using CngKey cng = CngKey.Import(bin, CngKeyBlobFormat.Pkcs8PrivateBlob, new CngProvider(Capi2Prov));
        cng.SetProperty(new CngProperty("Export Policy", BitConverter.GetBytes(3), CngPropertyOptions.None));
        using RSA rsa2 = new RSACng(cng);
        using X509Certificate2 newCert = cert.CopyWithPrivateKey(rsa2);
        Assert.IsTrue(newCert.HasPrivateKey);
        Assert.IsNull(newCert.PrivateKey);
        cng.Delete();
    }

    [TestCleanup]
    public void Cleanup() {
        rsa?.Dispose();
    }
}