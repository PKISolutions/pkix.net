using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.OcspClient.Tests.Properties;

namespace SysadminsLV.PKI.OcspClient.Tests;

[TestClass]
public class OCSPClient {
    [TestMethod]
    public void TestRevokedOCSP() {
        var cert = new X509Certificate2(Convert.FromBase64String(Resources.OcspRevoked));
        var req = new OCSPRequest(cert);
        OCSPResponse? resp = req.SendRequest();
        Assert.AreEqual(OCSPResponseStatus.Successful, resp.ResponseStatus);
        Assert.IsTrue(resp.SignatureIsValid);
        Assert.IsFalse(resp.SignerCertificateIsValid); // partial chain
        Assert.AreEqual(CertificateStatus.Revoked, resp.Responses[0].CertStatus);
    }
    [TestMethod]
    public void TestValidCert() {
        var cert = new X509Certificate2(Convert.FromBase64String(Resources.OcspValid));
        var req = new OCSPRequest(cert);
        OCSPResponse? resp = req.SendRequest();
        Assert.AreEqual(OCSPResponseStatus.Successful, resp.ResponseStatus);
        Assert.IsTrue(resp.SignatureIsValid);
        Assert.IsTrue(resp.SignerCertificateIsValid);
        Assert.AreEqual(CertificateStatus.Good, resp.Responses[0].CertStatus);
    }
    [TestMethod]
    public void TestEccCert() {
        using var cert = new X509Certificate2(Convert.FromBase64String(Resources.OcspEcc));
        var req = new OCSPRequest(cert);
        OCSPResponse? resp = req.SendRequest();
        Assert.AreEqual(OCSPResponseStatus.Successful, resp.ResponseStatus);
        //Assert.IsTrue(resp.SignatureIsValid);
        Assert.IsTrue(resp.SignerCertificateIsValid);
        Assert.AreEqual(CertificateStatus.Good, resp.Responses[0].CertStatus);
    }
    [TestMethod]
    public void TestOcspRequestSign() {

    }
}