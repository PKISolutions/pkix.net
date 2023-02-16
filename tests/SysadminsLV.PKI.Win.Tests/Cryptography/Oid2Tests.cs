using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Win.Tests.Cryptography {
    [TestClass]
    public class Oid2Tests {
        [TestMethod]
        public void TestHashAlgorithmGroup() {
            String strOid = "1.3.14.3.2.26";
            Oid2 oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.HashAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.3.14.3.2.26", oid.Value);
            Assert.AreEqual("sha1", oid.FriendlyName);

            strOid = "sha1";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.HashAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.3.14.3.2.26", oid.Value);
            Assert.AreEqual("sha1", oid.FriendlyName);
        }
        [TestMethod]
        public void TestSignatureAlgorithmGroup() {
            String strOid = "1.3.14.3.2.26";
            var oid = new Oid2(strOid, OidGroup.SignatureAlgorithm, false);
            Assert.AreEqual(OidGroup.SignatureAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.3.14.3.2.26", oid.Value);
            Assert.AreEqual("sha1NoSign", oid.FriendlyName);

            strOid = "sha1NoSign";
            oid = new Oid2(strOid, OidGroup.SignatureAlgorithm, false);
            Assert.AreEqual(OidGroup.SignatureAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.3.14.3.2.26", oid.Value);
            Assert.AreEqual("sha1NoSign", oid.FriendlyName);
        }
        [TestMethod]
        public void TestPublicKeyAlgorithmGroup() {
            String strOid = "1.2.840.113549.1.1.1";
            var oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.PublicKeyAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.2.840.113549.1.1.1", oid.Value);
            Assert.AreEqual("RSA", oid.FriendlyName);

            strOid = "RSA";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.PublicKeyAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.2.840.113549.1.1.1", oid.Value);
            Assert.AreEqual("RSA", oid.FriendlyName);
        }
        [TestMethod]
        public void TestRdnAttributeGroup() {
            String strOid = "2.5.4.3";
            var oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.Attribute, oid.OidGroup);
            Assert.AreEqual("2.5.4.3", oid.Value);
            Assert.AreEqual("CN", oid.FriendlyName);

            strOid = "CN";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.Attribute, oid.OidGroup);
            Assert.AreEqual("2.5.4.3", oid.Value);
            Assert.AreEqual("CN", oid.FriendlyName);
        }
        [TestMethod]
        public void TestEncryptionAlgorithmGroup() {
            String strOid = "1.3.14.3.2.7";
            var oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.EncryptionAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.3.14.3.2.7", oid.Value);
            Assert.AreEqual("des", oid.FriendlyName);

            strOid = "des";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.EncryptionAlgorithm, oid.OidGroup);
            Assert.AreEqual("1.3.14.3.2.7", oid.Value);
            Assert.AreEqual("des", oid.FriendlyName);
        }
        [TestMethod]
        public void TestExtensionOrAttributeGroup() {
            String strOid = "2.5.29.19";
            var oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.ExtensionOrAttribute, oid.OidGroup);
            Assert.AreEqual("2.5.29.19", oid.Value);
            Assert.AreEqual("Basic Constraints", oid.FriendlyName);

            strOid = "Basic Constraints";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.ExtensionOrAttribute, oid.OidGroup);
            Assert.AreEqual("2.5.29.19", oid.Value);
            Assert.AreEqual("Basic Constraints", oid.FriendlyName);
        }
        [TestMethod]
        public void TestApplicationPolicyGroup() {
            String strOid = "1.3.6.1.5.5.7.3.1";
            var oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.EnhancedKeyUsage, oid.OidGroup);
            Assert.AreEqual("1.3.6.1.5.5.7.3.1", oid.Value);
            Assert.AreEqual("Server Authentication", oid.FriendlyName);

            strOid = "Server Authentication";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.EnhancedKeyUsage, oid.OidGroup);
            Assert.AreEqual("1.3.6.1.5.5.7.3.1", oid.Value);
            Assert.AreEqual("Server Authentication", oid.FriendlyName);
        }
        [TestMethod]
        public void TestIssuancePolicyGroup() {
            String strOid = "2.5.29.32.0";
            var oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.Policy, oid.OidGroup);
            Assert.AreEqual("2.5.29.32.0", oid.Value);
            Assert.AreEqual("All issuance policies", oid.FriendlyName);

            strOid = "All issuance policies";
            oid = new Oid2(strOid, false);
            Assert.AreEqual(OidGroup.Policy, oid.OidGroup);
            Assert.AreEqual("2.5.29.32.0", oid.Value);
            Assert.AreEqual("All issuance policies", oid.FriendlyName);
        }
    }
}
