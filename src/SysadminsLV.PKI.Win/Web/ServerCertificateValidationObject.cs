using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PKI.Web {
    class ServerCertificateValidationObject {
        public String Url { get; set; }
        public Boolean StrictEKU { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public X509Chain SslChain { get; set; }
        public SslPolicyErrors SslErrors { get; set; }
    }
}
