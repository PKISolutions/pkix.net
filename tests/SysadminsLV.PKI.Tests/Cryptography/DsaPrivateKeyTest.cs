using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Tests.Cryptography;

[TestClass]
public class DsaPrivateKeyTest {
    #region Fields
    const String DsaPkcs1 = @"
MIIDVQIBAAKCAQEArZ71qR/SHd1oJ38vhqSIUnvn9i6hmeqQThzygocmPgxJ6RaM
d4UqQD2Jh/0Ei/8DJTWP5vnzCcBKxf32YOB8cgkxGSHj1iUHzHGbTg+xctokOTsA
l+KKhih24ZC5n/jLuKLosopKpXO/l2mV81iGxxpXVEsvtjpyf4zHpphasiBPL0vM
KeC+rFfdtoiJojZhgHmwk75Q238RhKsunAIfmsmf2uSU4c9Pv7xuEXUS2vylXl61
RVOsTfbqm8D4PHpS/EkwtsQQZb126cpUmERwssd2AStjiPk18oJ416RZy4oYsx0W
3jZ7weOM/z0cCXcoCut1q/APZBv6nTzL17kZnwIhAMSml/Bjm8p7JXgDT9rvYE+M
JPa0FNkZKmJb63NwGiwXAoIBAAfODM0QpACINWoqCR/fSLs+cfa2XdcT8La/gzKv
fCHdsD9HPFHwcuh9yg7EkMTQ64vnpnMKtJaWN1GC5/l4czcgNfehn+L0jOiqFtmT
Je1x1+0L7cti2ik2VuR+TKHuiGnzEEv95dbji5uzt5YlMpxoVw0rzuqnO1UCO42w
1VQSM1XrlY0gjFEjjDljhdIh3Ejx56Fvs9BQkufxqalOytbqyAdYnf7HLwiRjMwY
d0U4ZJA5VALoFzB8IHYj2W3LTriKXy8BpiFRFcTkrnNYWEVIl1+BYQc8Vc760CO3
5FvEEIgx2yH/DjRUBUvBkj/ZjmN1sC81jUpldcWw9hiVIEYCggEAZyWLyRlfkGHD
+y79k1aTSEDggGOvTSffKoqmL0PscCFL4ksVh2gT1/4jIJdcwScyW9Du2eFP+xEm
LxSKTjEgxpijjdt42w1wXwVGYmkV51SMru5C2OY1BCt/ACAIihXcXHtkddnLfc46
uOQImkopUxk0cAt4QMg4oP70x8nNjNBY3RFf2ZaU9QKC1S+BLnQFaMezDU/8N0y8
OQcyL4i+C4nRycF10PS4tujMGRZRK5sEijPlcT+0QMnu5vjTHr9PpQuko7xa3lHv
kwnivG9UAUPz/pq3pXKegml12xVgFjQUnpnwa+KTs2AMER730grjGw2hHPij7kat
miz330N1DAIgPJQpB+/EtR4i5NwTJNKrUVN5om2vyVMs8q9WPNS6KGY=
";
    const String DsaPkcs8 = @"
MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCtnvWpH9Id3Wgnfy+GpIhSe+f2
LqGZ6pBOHPKChyY+DEnpFox3hSpAPYmH/QSL/wMlNY/m+fMJwErF/fZg4HxyCTEZ
IePWJQfMcZtOD7Fy2iQ5OwCX4oqGKHbhkLmf+Mu4ouiyikqlc7+XaZXzWIbHGldU
Sy+2OnJ/jMemmFqyIE8vS8wp4L6sV922iImiNmGAebCTvlDbfxGEqy6cAh+ayZ/a
5JThz0+/vG4RdRLa/KVeXrVFU6xN9uqbwPg8elL8STC2xBBlvXbpylSYRHCyx3YB
K2OI+TXygnjXpFnLihizHRbeNnvB44z/PRwJdygK63Wr8A9kG/qdPMvXuRmfAiEA
xKaX8GObynsleANP2u9gT4wk9rQU2RkqYlvrc3AaLBcCggEAB84MzRCkAIg1aioJ
H99Iuz5x9rZd1xPwtr+DMq98Id2wP0c8UfBy6H3KDsSQxNDri+emcwq0lpY3UYLn
+XhzNyA196Gf4vSM6KoW2ZMl7XHX7Qvty2LaKTZW5H5Moe6IafMQS/3l1uOLm7O3
liUynGhXDSvO6qc7VQI7jbDVVBIzVeuVjSCMUSOMOWOF0iHcSPHnoW+z0FCS5/Gp
qU7K1urIB1id/scvCJGMzBh3RThkkDlUAugXMHwgdiPZbctOuIpfLwGmIVEVxOSu
c1hYRUiXX4FhBzxVzvrQI7fkW8QQiDHbIf8ONFQFS8GSP9mOY3WwLzWNSmV1xbD2
GJUgRgQiAiAfgFoZH+9xMu0KeFq8Fvv3rXDrXoBLumpKNzAgxsYDDg==
";
    #endregion

    Byte[] pkcs1PrivateKeyBin;
    Byte[] pkcs8PrivateKeyBin;
    DsaPrivateKey privateKey;
    DSA dsaPrivateKey;

    [TestInitialize]
    public void Initialize() {
        pkcs1PrivateKeyBin = Convert.FromBase64String(DsaPkcs1);
        pkcs8PrivateKeyBin = Convert.FromBase64String(DsaPkcs8);
    }

    [TestMethod]
    public void TestPkcs1() {
        // Arrange
        privateKey = new DsaPrivateKey(pkcs1PrivateKeyBin);
        // Act
        Oid oid = privateKey.Oid;
        // Assert
        Assert.AreEqual(AlgorithmOid.DSA, oid.Value);
        Assert.IsFalse(privateKey.PublicOnly);
    }
    [TestMethod]
    public void TestPkcs8() {
        // Arrange
        privateKey = new DsaPrivateKey(pkcs8PrivateKeyBin);
        // Act
        Oid oid = privateKey.Oid;
        // Assert
        Assert.AreEqual(AlgorithmOid.DSA, oid.Value);
        Assert.IsFalse(privateKey.PublicOnly);
    }
    [TestMethod]
    public void TestPkcs1AsymmetricKey() {
        // Arrange
        privateKey = new DsaPrivateKey(pkcs1PrivateKeyBin);
        // Act
        dsaPrivateKey = privateKey.GetAsymmetricKey() as DSA;
        // Assert
        // Assert
        Assert.IsInstanceOfType(dsaPrivateKey, typeof(DSA));
    }
    [TestMethod]
    public void TestPkcs8AsymmetricKey() {
        // Arrange
        privateKey = new DsaPrivateKey(pkcs8PrivateKeyBin);
        // Act
        dsaPrivateKey = privateKey.GetAsymmetricKey() as DSA;
        // Assert
        Assert.IsInstanceOfType(dsaPrivateKey, typeof(DSA));
    }

    [TestCleanup]
    public void Cleanup() {
        privateKey?.Dispose();
        dsaPrivateKey?.Dispose();
    }
}