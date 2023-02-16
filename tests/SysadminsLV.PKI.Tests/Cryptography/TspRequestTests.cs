using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SysadminsLV.PKI.Tests.Cryptography {
    [TestClass]
    public class TspRequestTests {
        Byte[] data;
        Oid reqHashOid;

        [TestInitialize]
        public void Initialize() {
            reqHashOid = new Oid("sha256");
            data = Encoding.Unicode.GetBytes("Microsoft.VisualStudio.TestTools.UnitTesting;");
            
            //var request = new TspRequest(reqHashOid, data);
        }

        [TestMethod]
        public void TestTspRequest() {
            
        }
        //[TestMethod]
        //public void TestTsp() {
        //    Byte[] a = default;
        //    var data = Encoding.Unicode.GetBytes("Microsoft.VisualStudio.TestTools.UnitTesting;");
        //    var h = new Oid("sha256");
        //    var req = new TspRequest(h, data);
        //    File.WriteAllBytes(@"C:\Users\vPodans\Desktop\tsq.bin", req.Encode());
        //    var rsp = req.SendRequest(new Uri("http://timestamp.digicert.com"));
        //    Debug.Write(rsp.RequestMessage.ToString());
        //}
    }
}
