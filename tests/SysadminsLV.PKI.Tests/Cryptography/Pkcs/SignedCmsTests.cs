using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.Pkcs;
[TestClass]
public class SignedCmsTests {
    Byte[] rawData;
    DefaultSignedPkcs7 cms;
    PkcsSignerInfo signerInfo, counter;

    [TestInitialize]
    public void Initialize() {
        rawData = Convert.FromBase64String(Resources.PKCS_TimeAuthSignExpired);
        cms = new DefaultSignedPkcs7(rawData);
        signerInfo = cms.SignerInfos[0];
        counter = new PkcsSignerInfo(signerInfo.UnauthenticatedAttributes[0].RawData);
    }
    [TestMethod]
    public void TestGeneralFields() {
        Assert.AreEqual(cms.DigestAlgorithms.Count, 1);
        Assert.AreEqual(cms.DigestAlgorithms[0].AlgorithmId.Value, AlgorithmOid.SHA1);

        Assert.AreEqual(cms.ContentType.Value, "1.3.6.1.4.1.311.2.1.4");
        Assert.AreEqual(cms.Content.Length, 88);

        Assert.AreEqual(cms.Certificates.Count, 4);
        Assert.AreEqual(cms.RevocationLists.Count, 0);

        // we check only count. Details are tested in another unit test
        Assert.AreEqual(cms.SignerInfos.Count, 1);
    }
    [TestMethod]
    public void TestSignerInfo() {
        Assert.AreEqual(signerInfo.Version, 1);
        Assert.AreEqual(signerInfo.Issuer.Type, SubjectIdentifierType.IssuerAndSerialNumber);
        Assert.AreEqual(signerInfo.AuthenticatedAttributes.Count, 4);
        Assert.AreEqual(signerInfo.UnauthenticatedAttributes.Count, 1);
        Assert.AreEqual(signerInfo.HashAlgorithm.AlgorithmId.Value, AlgorithmOid.SHA1);
        Assert.AreEqual(signerInfo.EncryptedHashAlgorithm.AlgorithmId.Value, AlgorithmOid.RSA);
        Assert.AreEqual(signerInfo.EncryptedHash.Length, 256);
        Assert.IsNull(signerInfo.Certificate);
    }
    [TestMethod]
    public void TestCounterSignerInfo() {
        Assert.AreEqual(counter.Version, 1);
        Assert.AreEqual(counter.Issuer.Type, SubjectIdentifierType.IssuerAndSerialNumber);
        Assert.AreEqual(counter.AuthenticatedAttributes.Count, 3);
        Assert.AreEqual(counter.UnauthenticatedAttributes.Count, 0);
        Assert.AreEqual(counter.HashAlgorithm.AlgorithmId.Value, AlgorithmOid.SHA1);
        Assert.AreEqual(counter.EncryptedHashAlgorithm.AlgorithmId.Value, AlgorithmOid.RSA);
        Assert.AreEqual(counter.EncryptedHash.Length, 128);
        Assert.IsNull(counter.Certificate);
    }
    [TestMethod]
    public void TestTimestampAttach() {
        TspRequest tspReq = new TspAuthenticodeRequest(cms.SignerInfos[0]) { TsaUrl = new Uri("http://timestamp.digicert.com") };
        TspResponse rsp = tspReq.SendRequest();

        var builder = new SignedCmsBuilder(cms);
        builder.AddTimestamp(rsp, 0);
        DefaultSignedPkcs7 cms2 = builder.Encode();
        Assert.AreEqual(cms2.SignerInfos[0].UnauthenticatedAttributes[0].Oid.Value, "1.2.840.113549.1.9.6");

        var c = new SignedCms();
        c.Decode(cms2.RawData);
        c.CheckHash();
        c.CheckSignature(cms2.Certificates, true);
    }
    [TestMethod]
    public void TestTimestampAttach2() {
        var tspReq = new TspRfc3161Request(new Oid("sha256"), cms.SignerInfos[0].EncryptedHash) {
            TsaUrl = new Uri("http://timestamp.digicert.com")
        };
        TspResponse rsp = tspReq.SendRequest();

        var builder = new SignedCmsBuilder(cms);
        builder.AddTimestamp(rsp, 0);
        DefaultSignedPkcs7 cms2 = builder.Encode();
        Assert.AreEqual(cms2.SignerInfos[0].UnauthenticatedAttributes[0].Oid.Value, "1.3.6.1.4.1.311.3.3.1");

        var c = new SignedCms();
        c.Decode(cms2.RawData);
        c.CheckHash();
        c.CheckSignature(cms2.Certificates, true);
    }
    [TestMethod]
    public void TestTimestampAttach3() {
        var cms2 = new DefaultSignedPkcs7(cms.RawData);
        cms2.AddTimestamp("http://timestamp.digicert.com", new Oid("sha256"));
        Assert.AreEqual(cms2.SignerInfos[0].UnauthenticatedAttributes[0].Oid.Value, "1.3.6.1.4.1.311.3.3.1");

        var c = new SignedCms();
        c.Decode(cms2.RawData);
        c.CheckHash();
        c.CheckSignature(c.Certificates, true);
    }
}
