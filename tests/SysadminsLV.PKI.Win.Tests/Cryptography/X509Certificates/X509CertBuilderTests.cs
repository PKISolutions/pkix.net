using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tools.MessageOperations;

namespace SysadminsLV.PKI.Win.Tests.Cryptography.X509Certificates; 
[TestClass]
public class X509CertBuilderTests {
    [TestMethod]
    public void TestBuilder() {
        var builder = new X509CertificateBuilder {
            FriendlyName = "Test Friendly Name",
            SubjectName = new X500DistinguishedName("CN=test"),
            PrivateKeyInfo = {
                ProviderName = "microsoft software key storage provider",
                Exportable = true
            }
        };
        X509Certificate2 cert = builder.Build();
        cert.DeletePrivateKey();
        var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
        Boolean status = MessageSigner.VerifyData(blob, cert.PublicKey);
        Assert.IsTrue(status);

        Assert.AreEqual("Test Friendly Name", cert.FriendlyName);
    }
    [TestMethod]
    public void TestBuilderExternalSigner() {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2 signer = store.Certificates.Find(X509FindType.FindByThumbprint,
            "E160F8D2E4DBE18908F9C4D3C8DA8BB57118FCC8", false)[0];
        store.Close();
        var builder = new X509CertificateBuilder();
        builder.SubjectName = new X500DistinguishedName("CN=test");
        builder.PrivateKeyInfo.ProviderName = "microsoft software key storage provider";
        builder.PrivateKeyInfo.Exportable = true;
        X509Certificate2 cert = builder.Build(signer);
        cert.DeletePrivateKey();
        var chain = new X509Chain();
        chain.Build(cert);
        Assert.AreEqual(2, chain.ChainElements.Count);
        var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
        Boolean status = MessageSigner.VerifyData(blob, signer.PublicKey);
        Assert.IsTrue(status);
    }
}
