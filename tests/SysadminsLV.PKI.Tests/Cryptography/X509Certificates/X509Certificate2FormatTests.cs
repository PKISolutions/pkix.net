using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509Certificate2FormatTests {
    [TestMethod]
    public void FormatECC() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Certificates.Cert_ECC));
        Console.WriteLine(cert.Format());
    }
}
