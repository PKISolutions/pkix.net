using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.CertificateTemplates;
using SysadminsLV.PKI.Management.ActiveDirectory;

namespace SysadminsLV.PKI.Win.Tests.CertificateTemplates {
    [TestClass]
    public class CertTmplTests {
        [TestMethod]
        public void Test() {
            foreach (ICertificateTemplateSource t in DsCertificateTemplate.GetAll()) {
                // need to figure out how to test this.
            }
        }
    }
}
