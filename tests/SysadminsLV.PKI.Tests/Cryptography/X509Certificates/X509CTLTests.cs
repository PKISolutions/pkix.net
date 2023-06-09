using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509CTLTests {
    X509Certificate2 signerCert;
    X509CertificateTrustList ctl;

    [TestInitialize]
    public void Initialize() {
        var bytes = Convert.FromBase64String(Resources.PFX_CTLSIGN_PWD_1);
        signerCert = new X509Certificate2(bytes, "1");
        genCTL();
    }

    [TestMethod]
    public void TestCreatedCTL() {
        Assert.AreEqual(1, ctl.Version);
        Assert.AreEqual(3, ctl.SubjectUsage.Count);
        Assert.AreEqual("My List", ctl.ListIdentifier);
        Assert.AreEqual(5, ctl.GetSequenceNumber());
        Assert.AreEqual(AlgorithmOid.SHA1, ctl.SubjectAlgorithm.Value);
        //ctl.ShowUI();
    }
    [TestMethod]
    public void TestSignature() {
        var cms = new SignedCms();
        cms.Decode(ctl.RawData);
        cms.CheckSignature(new X509Certificate2Collection(), true);
    }
    [TestMethod]
    public void TestTimestampAttach() {
        var cms = new DefaultSignedPkcs7(ctl.RawData);
        var tspReq = new TspAuthenticodeRequest(cms.SignerInfos[0]) {
            TsaUrl = new Uri("http://timestamp.digicert.com")
        };
        TspResponse rsp = tspReq.SendRequest();
        var builder = new SignedCmsBuilder(cms);
        builder.AddTimestamp(rsp, 0);
        cms = builder.Encode();
        ctl = new X509CertificateTrustList(cms.RawData);

        Assert.AreEqual(cms.SignerInfos[0].UnauthenticatedAttributes[0].Oid.Value, "1.2.840.113549.1.9.6");
    }
    [TestMethod]
    public void TestTimestampAttach2() {
        var ctl2 = new X509CertificateTrustList(ctl.RawData);
        ctl2.AddTimestamp("http://timestamp.digicert.com", new Oid("sha256"));
    }

    void genCTL() {
        var builder = new X509CertificateTrustListBuilder();
        builder.SubjectUsages.Add(new Oid("Server Authentication"));
        builder.SubjectUsages.Add(new Oid("Client Authentication"));
        builder.SubjectUsages.Add(new Oid("Root List Signer"));
        builder.ListIdentifier = "My List";
        builder.SequenceNumber = 5;
        builder.NextUpdate = DateTime.Now.AddYears(1);
        var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (X509Certificate2 cert in store.Certificates) {
            builder.Entries.Add(new X509CertificateTrustListEntry(cert, builder.HashAlgorithm));
        }
        store.Close();
        var signer = new CryptSigner(signerCert, Oid.FromOidValue(AlgorithmOid.SHA256, OidGroup.HashAlgorithm));
        ctl = builder.Sign(signer, null);
    }
}
