using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Win.Tests.Properties;

namespace SysadminsLV.PKI.Win.Tests.Cryptography.X509Certificates; 
[TestClass]
public class X509CRLBuilderTests {
    [TestMethod]
    public void TestX509CRLGeneratorHash() {
        var signer = new X509Certificate2(Convert.FromBase64String(Resources.CRLIssuer));
        X509CrlBuilder builder = getTbsCrl();
        X509CRL2 crl = builder.BuildAndHash(signer);
        Assert.AreEqual(2, crl.Version);
        Assert.AreEqual(signer.Subject, crl.Issuer);
        Assert.AreEqual(2, crl.Extensions.Count);
        Assert.AreEqual(100, crl.RevokedCertificates.Count);
        Assert.AreEqual("00", crl.RevokedCertificates[0].SerialNumber);
        Console.WriteLine(crl.ToString(true));

        var handle = crl.GetSafeContext();
        handle.Dispose();
        handle.Dispose();
    }
    [TestMethod]
    public void TestX509CRLGeneratorSignEcc() {
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2 cert = store.Certificates.Find(X509FindType.FindByThumbprint,
            "E160F8D2E4DBE18908F9C4D3C8DA8BB57118FCC8", false)[0];
        store.Close();
        X509CrlBuilder builder = getTbsCrl();
        X509CRL2 crl;
        using (var signerInfo = new MessageSigner(cert, new Oid2("sha512", false))) {
            crl = builder.BuildAndSign(signerInfo);
        }

        var blob = new SignedContentBlob(crl.RawData, ContentBlobType.SignedBlob);
        Boolean result = MessageSigner.VerifyData(blob, cert.PublicKey);
        Assert.IsTrue(result);
    }
    X509CrlBuilder getTbsCrl() {
        var dt1 = DateTime.ParseExact("120724142705", "yyMMddHHmmss", null);
        var dt2 = DateTime.ParseExact("100306111031", "yyMMddHHmmss", null);
        var dt3 = DateTime.ParseExact("150305111031", "yyMMddHHmmss", null);
        var crl = new X509CrlBuilder {
            Version = 2,
            ThisUpdate = dt2.ToLocalTime(),
            NextUpdate = dt3.ToLocalTime()
        };
        var crlEntries = new X509CRLEntryCollection();
        for (Int32 i = 0; i < 100; i++) {
            crlEntries.Add(new X509CRLEntry(i.ToString(), dt1.ToLocalTime(), 3));
        }
        crl.RevokedCertificates.AddRange(crlEntries);
        return crl;
    }
}
