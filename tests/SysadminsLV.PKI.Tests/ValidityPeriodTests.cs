using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.ADCS;

namespace SysadminsLV.PKI.Tests;

[TestClass]
public class ValidityPeriodTests {
    [TestMethod]
    public void Test1Year() {
        Int64 fileTime = -315360000000000;
        var vp = ValidityPeriod.FromFileTime(fileTime);

        Assert.AreEqual(365, vp.Validity.Days);
        Assert.AreEqual("1 years", vp.ValidityString);
    }
}
