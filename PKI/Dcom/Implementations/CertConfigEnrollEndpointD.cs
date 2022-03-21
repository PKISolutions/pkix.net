using System;

namespace SysadminsLV.PKI.Dcom.Implementations {
    class CertConfigEnrollEndpointD : ICertConfigEnrollEndpointD {

        internal CertConfigEnrollEndpointD(String dsUriString) {
            String[] tokens = dsUriString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 4) {
                throw new ArgumentException("Input string is not valid policy enrollment URI.");
            }

            Priority = Convert.ToInt32(tokens[0]);
            Authentication = (AdcsEnrollAuthenticationType)Convert.ToInt32(tokens[1]);
            RenewalOnly = Convert.ToBoolean(Byte.Parse(tokens[2]));
            Uri = tokens[3].TrimEnd();
            if (tokens.Length > 4) {
                KeyBasedRenewal = Convert.ToBoolean(Convert.ToInt32(tokens[4]));
            }
        }

        public String Uri { get; }
        public AdcsEnrollAuthenticationType Authentication { get; }
        public Int32 Priority { get; }
        public Boolean RenewalOnly { get; }
        public Boolean KeyBasedRenewal { get; }
        public String DsEncode() {
            return $"{Priority}\n{Authentication}\n{Convert.ToInt32(RenewalOnly)}\n{Uri}\n{Convert.ToInt32(KeyBasedRenewal)}";
        }
    }
}