using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509CrlEntryTests {
    const String ENCODED = "MC8CEB9sy4V7Jve7TuqqvabRY4wXDTIwMTAwNDIzNTcwMlowDDAKBgNVHRUEAwoBBA==";
    const String SERIAL_NUMBER = "1f6ccb857b26f7bb4eeaaabda6d1638c";
    const String REVOCATION_DATE = "05.10.2020 02:57:02";
    const Int32 REASON_CODE = 4;

    [TestMethod]
    public void TestEncode() {
        var entry = new X509CRLEntry(SERIAL_NUMBER, DateTime.Parse(REVOCATION_DATE), REASON_CODE);
        Assert.AreEqual(SERIAL_NUMBER, entry.SerialNumber);
        Assert.AreEqual(REVOCATION_DATE, entry.RevocationDate.ToString());
        Assert.AreEqual(REASON_CODE, 4);
        Assert.AreEqual(ENCODED, Convert.ToBase64String(entry.Encode()));
    }
    [TestMethod]
    public void TestDecode() {
        String b64 = "MC8CEB9sy4V7Jve7TuqqvabRY4wXDTIwMTAwNDIzNTcwMlowDDAKBgNVHRUEAwoBBA==";
        var entry = new X509CRLEntry(new Asn1Reader(Convert.FromBase64String(b64)));
        Assert.AreEqual(SERIAL_NUMBER, entry.SerialNumber);
        Assert.AreEqual(REVOCATION_DATE, entry.RevocationDate.ToString());
        Assert.AreEqual(REASON_CODE, 4);
        Assert.AreEqual(ENCODED, Convert.ToBase64String(entry.Encode()));
    }
}
