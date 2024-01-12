using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.ADCS;

namespace SysadminsLV.PKI.Tests;

[TestClass]
public class ValidityPeriodTests {
    [TestMethod]
    public void TestFromBinary() {
        Byte[] fileTime = { 0, 64, 57, 135, 46, 225, 254, 255 };
        var vp = ValidityPeriod.FromFileTime(fileTime);

        Assert.AreEqual(365, vp.Validity.Days);
        Assert.AreEqual(0, vp.Validity.Hours);
        Assert.AreEqual(0, vp.Validity.Minutes);
        Assert.AreEqual(0, vp.Validity.Milliseconds);
        Assert.AreEqual("1 years", vp.ValidityString);
    }
    [TestMethod]
    public void TestFromLong() {
        const Int64 fileTime = -315360000000000;
        var vp = ValidityPeriod.FromFileTime(fileTime);

        Assert.AreEqual(365, vp.Validity.Days);
        Assert.AreEqual(0, vp.Validity.Hours);
        Assert.AreEqual(0, vp.Validity.Minutes);
        Assert.AreEqual(0, vp.Validity.Milliseconds);
        Assert.AreEqual("1 years", vp.ValidityString);
    }
    [TestMethod]
    public void TestFromTimeSpan() {
        const Int64 fileTime = -315360000000000;
        var reference = ValidityPeriod.FromFileTime(fileTime);

        var vp = ValidityPeriod.FromTimeSpan(reference.Validity);
        Assert.IsTrue(Equals(reference.Validity, vp.Validity));
        Assert.AreEqual(reference.ValidityString, vp.ValidityString);
    }
}
