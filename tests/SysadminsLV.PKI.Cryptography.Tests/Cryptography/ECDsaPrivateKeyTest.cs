using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Tests.Cryptography {
    [TestClass]
    public class ECDsaPrivateKeyTest {
        #region Fields
        public String ecdsaNamedString = @"
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvKMujP6GKFtOCu4f
Zw1LTxKjLBLlwL2SJwqMxzV2p1OhRANCAAQsNwRMPO++oIKZ9L9Tk3REdwNonGAM
G7yVrgLhQ4zjZtEkHIMd93UE0wuu5zfAH85rHU+li5SQPuzi+4c8KV8S
";
        public String ecdsaExplicitParams1 = @"
MIIBIAIBAQQYd8yhaE899FaH3sw8aD4F/vtpMVBLfVqmoIHKMIHHAgEBMCQGByqG
SM49AQECGQD////////////////////+//////////8wSwQY////////////////
/////v/////////8BBgiEj3COVoFyqdCPa7MyUdgp9RiJWvVaRYDFQDEaWhENd6z
eMS2XKlZHipXYwWaLgQxBH0pd4EAxlodoXg3FliNziuLSu6OIo8YljipDyJjczcz
S0nctmptyPmXisp2SKlDsAIZAP///////////////3pi0DHIP0KU9kDsEwIBAaE0
AzIABBsl8ZSGJqcUpVoP8zekF92DGqDBMERcHhCXmgPXchP+ljybXbzYKINgxbp5
0g9/pw==
";
        public String ecdsaExplicitParams2 = @"
MIIBMAIBADCB0wYHKoZIzj0CATCBxwIBATAkBgcqhkjOPQEBAhkA////////////
/////////v//////////MEsEGP////////////////////7//////////AQYIhI9
wjlaBcqnQj2uzMlHYKfUYiVr1WkWAxUAxGloRDXes3jEtlypWR4qV2MFmi4EMQR9
KXeBAMZaHaF4NxZYjc4ri0rujiKPGJY4qQ8iY3M3M0tJ3LZqbcj5l4rKdkipQ7AC
GQD///////////////96YtAxyD9ClPZA7BMCAQEEVTBTAgEBBBiKtwssqrxHY/gu
KDD4QgmyLDKaqBv2wEWhNAMyAAT5j6o+ojeB6jaFAfx4rtGf5hYbT1N6NnlAWiP1
+bEWtTJiEVqnpeZN0m0SLybIGZY=
";
        Byte[] ecdsaNamedBin;
        Byte[] ecdsaExplicit1Bin;
        Byte[] ecdsaExplicit2Bin;
        ECDsaPrivateKey privateKey;
        ECDsa ecdsaPrivateKey;
        #endregion

        [TestInitialize]
        public void Initialize() {
            ecdsaNamedBin = Convert.FromBase64String(ecdsaNamedString);
            ecdsaExplicit1Bin = Convert.FromBase64String(ecdsaExplicitParams1);
            ecdsaExplicit2Bin = Convert.FromBase64String(ecdsaExplicitParams2);
        }

        [TestMethod]
        public void TestNamedEcdsaCurve() {
            // Arrange
            privateKey = new ECDsaPrivateKey(ecdsaNamedBin);
            // Act
            Oid oid = privateKey.CurveOid;
            // Assert
            Assert.AreEqual("1.2.840.10045.3.1.7", oid.Value);
        }
        [TestMethod]
        public void TestExplicitCurve1() {
            // Arrange
            privateKey = new ECDsaPrivateKey(ecdsaExplicit2Bin);
            // Act
            Oid oid = privateKey.CurveOid;
            Int32 lengthX = privateKey.CoordinateX.Length;
            Int32 lengthY = privateKey.CoordinateY.Length;
            // Assert
            Assert.IsNull(oid);
            Assert.IsNotNull(privateKey.CoordinateX);
            Assert.IsNotNull(privateKey.CoordinateY);
            Assert.AreEqual(lengthX, lengthY);
            Assert.IsFalse(privateKey.PublicOnly);
        }
        [TestMethod]
        public void TestExplicitCurveAsymmetricKey() {
            // Arrange
            privateKey = new ECDsaPrivateKey(ecdsaExplicit2Bin);
            // Act
            ecdsaPrivateKey = privateKey.GetAsymmetricKey() as ECDsa;
            // Assert
            Assert.IsInstanceOfType(ecdsaPrivateKey, typeof(ECDsa));
        }
        [TestMethod]
        public void TestExplicitCurveParams() {
            // Arrange
            privateKey = new ECDsaPrivateKey(ecdsaExplicit2Bin);
            // Act
            ecdsaPrivateKey = privateKey.GetAsymmetricKey() as ECDsa;
            ECParameters param = ecdsaPrivateKey.ExportParameters(true);
            param.Validate();
            // Assert
        }

        [TestMethod]
        public void TestEcdsaReuse() {
            // Arrange
            privateKey = new ECDsaPrivateKey(ecdsaNamedBin);
            // Act
            ecdsaPrivateKey = privateKey.GetAsymmetricKey() as ECDsa;
            var ecdsa2 = privateKey.GetAsymmetricKey() as ECDsa;
            // Assert
            Assert.AreSame(ecdsaPrivateKey, ecdsa2);
        }

        [TestCleanup]
        public void Cleanup() {
            privateKey?.Dispose();
            ecdsaPrivateKey?.Dispose();
        }
    }
}
