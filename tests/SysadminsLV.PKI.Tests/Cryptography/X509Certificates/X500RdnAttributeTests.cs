using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X500RdnAttributeTests {
    [TestMethod]
    public void TestCollection() {
        var rawData = Convert.FromBase64String(Resources.X500Name);
        var collection = new X500RdnAttributeCollection();
        collection.Decode(rawData);
        var x500name = collection.ToDistinguishedName();
        var col = x500name.GetRdnAttributes();
    }
}