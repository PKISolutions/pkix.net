using System;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Tests.Properties;

namespace SysadminsLV.PKI.Tests.Cryptography.X509Certificates;
[TestClass]
public class X509CertificateRequestTests {
    [TestMethod]
    public void ReadPkcs7() {
        var pkcs10 = new X509CertificateRequest(Convert.FromBase64String(Resources.pkcs10req));
        var pkcs7 = new X509CertificateRequest(Convert.FromBase64String(Resources.pkcs7req));
        var Pkcs7Gen = new DefaultSignedPkcs7(Convert.FromBase64String(Resources.pkcs7generic));
        var cngreq = new X509CertificateRequest(Convert.FromBase64String(Resources.CNGReq));
        String str = pkcs7.ToString();
    }
    [TestMethod]
    public void TestRequest() {
        var req = new X509CertificateRequest(Convert.FromBase64String(SignerData.REQ10DSA));
        var req2 = new X509CertificateRequestPkcs10(Convert.FromBase64String(SignerData.REQ10DSA));
        var str = req2.Format();
        Debug.Write(req2.Format());
    }
}
