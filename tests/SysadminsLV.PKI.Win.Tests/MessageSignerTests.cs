using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PKI.Test;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;
using SysadminsLV.PKI.Win.Tests.Properties;

namespace SysadminsLV.PKI.Win.Tests {
    [TestClass]
    public class MessageSignerTests {
        void signAndVerifyValid(MessageSigner signer) {
            var data = new SignedContentBlob(signer.SignerCertificate.RawData, ContentBlobType.SignedBlob);
            Byte[] sig = signer.SignData(data.ToBeSignedData);
            Boolean verify = signer.VerifyData(data.ToBeSignedData, sig);
            Assert.AreEqual(true, verify);
            data.Sign(signer);
            verify = MessageSigner.VerifyData(data, signer.SignerCertificate.PublicKey);
            Assert.AreEqual(true, verify);
        }
        void signAndVerifyInvalid(MessageSigner signer) {
            var blob = new SignedContentBlob(signer.SignerCertificate.RawData, ContentBlobType.SignedBlob);
            Byte[] sig = signer.SignData(blob.ToBeSignedData);
            // tamper signature
            sig[0] = 0;
            Boolean verify = signer.VerifyData(blob.ToBeSignedData, sig);
            Assert.AreNotEqual(true, verify);
        }
        void hashTestSeries(X509Certificate2 cert, RSASignaturePadding padding) {
            // SHA1
            using (var signer = new MessageSigner(cert, new Oid2("sha1", false))) {
                signer.PaddingScheme = padding;
                signAndVerifyValid(signer);
                signAndVerifyInvalid(signer);
            }

            // SHA256
            using (var signer = new MessageSigner(cert, new Oid2("sha256", false))) {
                signer.PaddingScheme = padding;
                signAndVerifyValid(signer);
                signAndVerifyInvalid(signer);
            }

            // SHA384
            using (var signer = new MessageSigner(cert, new Oid2("sha384", false))) {
                signer.PaddingScheme = padding;
                signAndVerifyValid(signer);
                signAndVerifyInvalid(signer);
            }

            // SHA512
            using (var signer = new MessageSigner(cert, new Oid2("sha512", false))) {
                signer.PaddingScheme = padding;
                signAndVerifyValid(signer);
                signAndVerifyInvalid(signer);
            }
        }

        [TestMethod]
        public void TestSignatureCngDsa() {
            var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngDsa), "1");
            hashTestSeries(cert, RSASignaturePadding.Pkcs1);
            cert.DeletePrivateKey();
        }
        [TestMethod]
        public void TestSignatureLegacyRsa() {
            var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertLegacyRsa), "1");
            hashTestSeries(cert, RSASignaturePadding.Pkcs1);
            cert.DeletePrivateKey();
        }
        [TestMethod]
        public void TestSignatureCngRsa() {
            var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngRsa), "1");
            hashTestSeries(cert, RSASignaturePadding.Pkcs1);
            //hashTestSeries(cert, SignaturePadding.PSS);
            cert.DeletePrivateKey();
        }
        [TestMethod]
        public void TestRsaPss() {
            var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngRsaPss), "1");
            cert.DeletePrivateKey();
            var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
            Boolean result = MessageSigner.VerifyData(blob, cert.PublicKey);
            Assert.AreEqual(true, result);
        }
        [TestMethod]
        public void TestSignedBlob() {
            var cert = new X509Certificate2(Convert.FromBase64String(Resources.SigningCertCngRsa), "1");
            var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
            blob.Sign(new MessageSigner(cert, new Oid2("sha1", OidGroup.HashAlgorithm, false)));
            cert.DeletePrivateKey();
            Boolean result = MessageSigner.VerifyData(blob, cert.PublicKey);
            Assert.AreEqual(true, result);
            blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
            result = MessageSigner.VerifyData(blob, cert.PublicKey);
            Assert.AreEqual(true, result);
        }
        [TestMethod]
        public void TestEcdsaP256Sha384Specified() {
            var blob = new SignedContentBlob(Convert.FromBase64String(SignerData.ECDSAP256SHA384SPECIFIED), ContentBlobType.SignedBlob);
            var req = new X509CertificateRequest(blob.Encode());
            Assert.AreEqual(req.SignatureIsValid, true);
            Boolean result = MessageSigner.VerifyData(blob, req.PublicKey);
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
}
