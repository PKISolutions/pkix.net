using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Tests.Cryptography;

[TestClass]
public class RsaPublicKeyTest {
    #region Fields
    String pkcs1Key = @"
MIIBCAKCAQEA3p3X6lcYSaFb69dfSIbqvt3/5O9nHPRlaLNXcaBed7vtm0npcIA9
VhhjCG/a8szQP38CVCJUENiygdTAdT1Lf8d3wz54qxoDtSBrL2orscWIfsS7HrDB
2EUnb6o3WPeHJtfYLfapF7cfcjZOphc/ZZiS2ypuXaL+iOAL3n/ljRXh68s61eIS
ohMt2I6vXxI9oAgFCLZcpWU4BEWZHqNgYHTFQaVyYhtixR9vXxpCvgJRZaiuIxhq
/HgDqU1/gMP6q1r8oUCkyhkW/rLI715zDe53vZr2eZi8sQdnohUN3aBYxkR7Cj5i
KF+6QQdTWM8Rfjh0xfj/tWmQj4R06pcbrwIBAw==
";
    String pkcs8Key = @"
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA3p3X6lcYSaFb69dfSIbq
vt3/5O9nHPRlaLNXcaBed7vtm0npcIA9VhhjCG/a8szQP38CVCJUENiygdTAdT1L
f8d3wz54qxoDtSBrL2orscWIfsS7HrDB2EUnb6o3WPeHJtfYLfapF7cfcjZOphc/
ZZiS2ypuXaL+iOAL3n/ljRXh68s61eISohMt2I6vXxI9oAgFCLZcpWU4BEWZHqNg
YHTFQaVyYhtixR9vXxpCvgJRZaiuIxhq/HgDqU1/gMP6q1r8oUCkyhkW/rLI715z
De53vZr2eZi8sQdnohUN3aBYxkR7Cj5iKF+6QQdTWM8Rfjh0xfj/tWmQj4R06pcb
rwIBAw==
";
    String fakeOidPkcs8 = @"
MIIBIDANBgkqhkiG9w0BAQIFAAOCAQ0AMIIBCAKCAQEA3p3X6lcYSaFb69dfSIbq
vt3/5O9nHPRlaLNXcaBed7vtm0npcIA9VhhjCG/a8szQP38CVCJUENiygdTAdT1L
f8d3wz54qxoDtSBrL2orscWIfsS7HrDB2EUnb6o3WPeHJtfYLfapF7cfcjZOphc/
ZZiS2ypuXaL+iOAL3n/ljRXh68s61eISohMt2I6vXxI9oAgFCLZcpWU4BEWZHqNg
YHTFQaVyYhtixR9vXxpCvgJRZaiuIxhq/HgDqU1/gMP6q1r8oUCkyhkW/rLI715z
De53vZr2eZi8sQdnohUN3aBYxkR7Cj5iKF+6QQdTWM8Rfjh0xfj/tWmQj4R06pcb
rwIBAw==
";
    Byte[] pkcs1Bin;
    Byte[] pkcs8Bin;
    Byte[] fakeOidPcks8Bin;
    RsaPublicKey publicKey;
    RSA rsaPublicKey;
    #endregion

    [TestInitialize]
    public void Initialize() {
        pkcs1Bin = Convert.FromBase64String(pkcs1Key);
        pkcs8Bin = Convert.FromBase64String(pkcs8Key);
        fakeOidPcks8Bin = Convert.FromBase64String(fakeOidPkcs8);
    }

    [TestMethod]
    public void TestRsaPublicKeyPkcs1() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs1Bin, KeyPkcsFormat.Pkcs1);
        // Act

        // Assert
        Assert.AreEqual(publicKey.Oid.Value, AlgorithmOid.RSA);
        Assert.IsTrue(publicKey.PublicOnly);
    }

    [TestMethod]
    public void TestRsaPublicKeyPkcs8() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs8Bin, KeyPkcsFormat.Pkcs8);
        // Act

        // Assert
        Assert.AreEqual(publicKey.Oid.Value, AlgorithmOid.RSA);
        Assert.IsTrue(publicKey.PublicOnly);
    }
        
    [TestMethod]
    public void TestPublicExponentLength() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs8Bin, KeyPkcsFormat.Pkcs8);
        // Act

        // Assert
        Assert.AreEqual(publicKey.PublicExponent.Length, 1);
    }
    [TestMethod]
    public void TestModulusLength() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs8Bin, KeyPkcsFormat.Pkcs8);
        // Act

        // Assert
        Assert.AreEqual(publicKey.Modulus.Length, 256);
    }

    [TestMethod]
    public void TestRsaPublicKeyType() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs1Bin, KeyPkcsFormat.Pkcs1);
        // Act
        rsaPublicKey = publicKey.GetAsymmetricKey() as RSA;
        // Assert
        Assert.IsNotNull(rsaPublicKey);
    }

    [TestMethod]
    public void TestRsaReuse() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs1Bin, KeyPkcsFormat.Pkcs1);
        // Act
        rsaPublicKey = publicKey.GetAsymmetricKey() as RSA;
        var rsa2 = publicKey.GetAsymmetricKey() as RSA;
        // Assert
        Assert.AreSame(rsaPublicKey, rsa2);

    }

    [TestMethod, ExpectedException(typeof(ArgumentNullException))]
    public void TestNullParameter() {
        // Act
        publicKey = new RsaPublicKey(null, KeyPkcsFormat.Pkcs8);
    }

    [TestMethod, ExpectedException(typeof(ArgumentOutOfRangeException))]
    public void TestInvalidKeyFormat() {
        // Act
        publicKey = new RsaPublicKey(pkcs1Bin, (KeyPkcsFormat)3);
    }

    [TestMethod, ExpectedException(typeof(ArgumentException))]
    public void TestFakeRsaOid() {
        // Act
        publicKey = new RsaPublicKey(fakeOidPcks8Bin, KeyPkcsFormat.Pkcs8);
    }

    [TestMethod, ExpectedException(typeof(Asn1InvalidTagException))]
    public void TestRsaPkcs1Against8() {
        // Act
        publicKey = new RsaPublicKey(pkcs1Bin, KeyPkcsFormat.Pkcs8);
    }

    [TestMethod, ExpectedException(typeof(Asn1InvalidTagException))]
    public void TestRsaPkcs8Against1() {
        // Arrange

        // Act
        publicKey = new RsaPublicKey(pkcs8Bin, KeyPkcsFormat.Pkcs1);
    }

    [TestMethod]
    public void RsaCanEncrypt() {
        // Arrange
        publicKey = new RsaPublicKey(pkcs1Bin, KeyPkcsFormat.Pkcs1);
        // Act
        rsaPublicKey = (RSA)publicKey.GetAsymmetricKey();
        Byte[] encryptedBytes = rsaPublicKey.Encrypt(new Byte[]{ 0 }, RSAEncryptionPadding.Pkcs1);
        // Assert
        Assert.AreEqual(encryptedBytes.Length, 256);
    }

    [TestCleanup]
    public void Cleanup() {
        publicKey?.Dispose();
        rsaPublicKey?.Dispose();
    }
}