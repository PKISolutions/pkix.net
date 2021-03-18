using System;

namespace PKI.Cryptography {
    public class X509AttributeOid {
        public const String ContentType             = "1.2.840.113549.1.9.3";
        public const String MessageDigest           = "1.2.840.113549.1.9.4";
        public const String RenewalCertificate      = "1.3.6.1.4.1.311.13.1";
        public const String EnrollmentNameValuePair = "1.3.6.1.4.1.311.13.2.1";
        public const String CspInformation          = "1.3.6.1.4.1.311.13.2.2";
        public const String OSVersion               = "1.3.6.1.4.1.311.13.2.3";
        public const String ClientInformation       = "1.3.6.1.4.1.311.21.20";
        public const String NTPrincipal             = "1.3.6.1.4.1.311.20.2.3";
        public const String NTDSReplication         = "1.3.6.1.4.1.311.25.1";
        public const String PropSHA1Hash            = "1.3.6.1.4.1.311.10.11.3";
        public const String PropMD5Hash             = "1.3.6.1.4.1.311.10.11.4";
        public const String PropEKU                 = "1.3.6.1.4.1.311.10.11.9";
        public const String PropFriendlyName        = "1.3.6.1.4.1.311.10.11.11";
        public const String PropKeyIdentifier       = "1.3.6.1.4.1.311.10.11.20";
        public const String PropSubjectNameMD5Hash  = "1.3.6.1.4.1.311.10.11.29";

    }
}