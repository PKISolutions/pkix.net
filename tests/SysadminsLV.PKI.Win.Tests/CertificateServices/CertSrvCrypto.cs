using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Management.CertificateServices;

namespace PKI.Test.CertificateServices {
    [TestClass]
    public class CertSrvCrypto {
        CertSrvCryptographyConfig crypto;

        [TestInitialize]
        public void Initialize() {
            crypto = new CertSrvCryptographyConfig("hq-s-testca");
        }

        [TestMethod]
        public void ReadCrypto() {
            Assert.AreEqual("Microsoft Software Key Storage Provider", crypto.SigningProvider.Name);
            Assert.AreEqual(AlgorithmOid.SHA384, crypto.HashingAlgorithm.Value);
            Assert.AreEqual(AlgorithmOid.ECDSA_P384, crypto.SigningPublicKeyAlgorithm.Value);

            Assert.AreEqual("Microsoft Software Key Storage Provider", crypto.EncryptionProvider.Name);
            Assert.AreEqual(AlgorithmOid.ECDSA_P384, crypto.EncryptionPublicKeyAlgorithm.Value);
            Assert.AreEqual(384, crypto.EncryptionPublicKeyLength);
            Assert.AreEqual(AlgorithmOid.AES256, crypto.EncryptionAlgorithm.Value);
            Assert.AreEqual(256, crypto.EncryptionKeyLength);
        }
        [TestMethod]
        public void ChangeCrypto() {
            crypto.HashingAlgorithm = new Oid(AlgorithmOid.SHA512);
            Assert.AreEqual(AlgorithmOid.SHA512, crypto.HashingAlgorithm.Value);
            crypto.SigningPublicKeyAlgorithm = new Oid(AlgorithmOid.RSA);
            Assert.AreEqual(AlgorithmOid.RSA, crypto.SigningPublicKeyAlgorithm.Value);

            // DSA
            crypto.EncryptionPublicKeyAlgorithm = new Oid(AlgorithmOid.DSA);
            Assert.AreEqual(AlgorithmOid.DSA, crypto.EncryptionPublicKeyAlgorithm.Value);
            Assert.AreEqual(1024, crypto.EncryptionPublicKeyLength);

            // RSA
            crypto.EncryptionPublicKeyAlgorithm = new Oid(AlgorithmOid.RSA);
            Assert.AreEqual(AlgorithmOid.RSA, crypto.EncryptionPublicKeyAlgorithm.Value);
            Assert.AreEqual(2048, crypto.EncryptionPublicKeyLength);

            // ECDSA_P256
            crypto.EncryptionPublicKeyAlgorithm = new Oid(AlgorithmOid.ECDSA_P256);
            Assert.AreEqual(AlgorithmOid.ECDSA_P256, crypto.EncryptionPublicKeyAlgorithm.Value);
            Assert.AreEqual(256, crypto.EncryptionPublicKeyLength);

            // ECDSA_P384
            crypto.EncryptionPublicKeyAlgorithm = new Oid(AlgorithmOid.ECDSA_P384);
            Assert.AreEqual(AlgorithmOid.ECDSA_P384, crypto.EncryptionPublicKeyAlgorithm.Value);
            Assert.AreEqual(384, crypto.EncryptionPublicKeyLength);

            // ECDSA_P521
            crypto.EncryptionPublicKeyAlgorithm = new Oid(AlgorithmOid.ECDSA_P521);
            Assert.AreEqual(AlgorithmOid.ECDSA_P521, crypto.EncryptionPublicKeyAlgorithm.Value);
            Assert.AreEqual(521, crypto.EncryptionPublicKeyLength);

            // DES
            crypto.EncryptionAlgorithm = new Oid(AlgorithmOid.DES);
            Assert.AreEqual(AlgorithmOid.DES, crypto.EncryptionAlgorithm.Value);
            Assert.AreEqual(56, crypto.EncryptionKeyLength);

            // 3DES
            crypto.EncryptionAlgorithm = new Oid(AlgorithmOid.TrippleDES);
            Assert.AreEqual(AlgorithmOid.TrippleDES, crypto.EncryptionAlgorithm.Value);
            Assert.AreEqual(168, crypto.EncryptionKeyLength);

            // AES 128
            crypto.EncryptionAlgorithm = new Oid(AlgorithmOid.AES128);
            Assert.AreEqual(AlgorithmOid.AES128, crypto.EncryptionAlgorithm.Value);
            Assert.AreEqual(128, crypto.EncryptionKeyLength);

            // AES 192
            crypto.EncryptionAlgorithm = new Oid(AlgorithmOid.AES192);
            Assert.AreEqual(AlgorithmOid.AES192, crypto.EncryptionAlgorithm.Value);
            Assert.AreEqual(192, crypto.EncryptionKeyLength);

            // AES 256
            crypto.EncryptionAlgorithm = new Oid(AlgorithmOid.AES256);
            Assert.AreEqual(AlgorithmOid.AES256, crypto.EncryptionAlgorithm.Value);
            Assert.AreEqual(256, crypto.EncryptionKeyLength);
        }

        [TestMethod]
        public void SaveCrypto() {
            crypto.Commit(false);
        }
    }
}
