using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Utils.CLRExtensions;

namespace SysadminsLV.PKI.Win.Tests.Cryptography.X509Certificates {
    [TestClass]
    public class X509Certificate2PropertiesTest {
        [TestMethod]
        public void GetCertPropertyList() {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = store.Certificates[0];
            Console.WriteLine(cert.IssuerName.FormatReverse(false));
            Console.WriteLine(cert.IssuerName.FormatReverse(true));
            Console.WriteLine(cert.Extensions.Format());
            Console.WriteLine(cert.Format());
            store.Close();
            X509CertificatePropertyType[] list = cert.GetCertificateContextPropertyList();
            X509CertificateContextPropertyCollection props = cert.GetCertificateContextProperties();
        }
    }
}
