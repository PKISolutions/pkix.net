using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography;
[TestClass]
public class CryptSignerTests {
    void signAndVerifyValid(ICryptSigner signer) {
        var data = new SignedContentBlob(signer.SignerCertificate.RawData, ContentBlobType.SignedBlob);
        Byte[] sig = signer.SignData(data.ToBeSignedData);
        Boolean verify = signer.VerifyData(data.ToBeSignedData, sig);
        Assert.AreEqual(true, verify);
        data.Sign(signer);
        verify = CryptSigner.VerifyData(data, signer.SignerCertificate.PublicKey);
        Assert.AreEqual(true, verify);
    }
    void signAndVerifyInvalid(ICryptSigner signer) {
        var blob = new SignedContentBlob(signer.SignerCertificate.RawData, ContentBlobType.SignedBlob);
        Byte[] sig = signer.SignData(blob.ToBeSignedData);
        // tamper signature
        sig[0] = 0;
        Boolean verify = signer.VerifyData(blob.ToBeSignedData, sig);
        Assert.AreNotEqual(true, verify);
    }
    void hashTestSeries(X509Certificate2 cert, RSASignaturePadding padding) {
        // SHA1
        using (var signer = new CryptSigner(cert, new Oid(AlgorithmOid.SHA1))) {
            signer.PaddingScheme = padding;
            signAndVerifyValid(signer);
            signAndVerifyInvalid(signer);
        }

        // SHA256
        using (var signer = new CryptSigner(cert, new Oid(AlgorithmOid.SHA256))) {
            signer.PaddingScheme = padding;
            signAndVerifyValid(signer);
            signAndVerifyInvalid(signer);
        }

        // SHA384
        using (var signer = new CryptSigner(cert, new Oid(AlgorithmOid.SHA384))) {
            signer.PaddingScheme = padding;
            signAndVerifyValid(signer);
            signAndVerifyInvalid(signer);
        }

        // SHA512
        using (var signer = new CryptSigner(cert, new Oid(AlgorithmOid.SHA512))) {
            signer.PaddingScheme = padding;
            signAndVerifyValid(signer);
            signAndVerifyInvalid(signer);
        }
    }
    [TestMethod]
    public void TestSignatureCngDsa() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngDsa), "1");
        hashTestSeries(cert, RSASignaturePadding.Pkcs1);
    }
    [TestMethod]
    public void TestSignatureLegacyRsa() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertLegacyRsa), "1");
        hashTestSeries(cert, RSASignaturePadding.Pkcs1);
    }
    [TestMethod]
    public void TestSignatureCngRsa() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngRsa), "1");
        hashTestSeries(cert, RSASignaturePadding.Pkcs1);
    }
    [TestMethod]
    public void TestRsaPss() {
        var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngRsaPss), "1");
        var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
        Boolean result = CryptSigner.VerifyData(blob, cert.PublicKey);
        Assert.AreEqual(true, result);
    }
    [TestMethod]
    public void TestSignedBlob() {
        var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngRsa), "1");
        var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
        blob.Sign(new CryptSigner(cert, new Oid(AlgorithmOid.SHA1)));
        Boolean result = CryptSigner.VerifyData(blob, cert.PublicKey);
        Assert.AreEqual(true, result);
        blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
        result = CryptSigner.VerifyData(blob, cert.PublicKey);
        Assert.AreEqual(true, result);
    }
    [TestMethod]
    public void TestEcdsaP256Sha384Specified() {
        var blob = new SignedContentBlob(Convert.FromBase64String(SignerData.ECDSAP256SHA384SPECIFIED), ContentBlobType.SignedBlob);
        var req = new X509CertificateRequest(blob.Encode());
        Assert.AreEqual(req.SignatureIsValid, true);
        Boolean result = CryptSigner.VerifyData(blob, req.PublicKey);
        Assert.AreEqual(true, result);
    }
    //[TestMethod]
    //public void TestEccCngKeyExport() {
    //    var a = CngKeyExportFix.ConvertPfx2Pkcs8(Convert.FromBase64String(Resources.SigningCertCngDsa), "1");
    //    Console.WriteLine(a.Length);
    //}
    //[TestMethod]
    //public void TestRsaCngKeyExport() {
    //    var a = CngKeyExportFix.ConvertPfx2Pkcs8(Convert.FromBase64String(Resources.SigningCertCngRsa), "1");
    //    Console.WriteLine(a.Length);
    //}
}
