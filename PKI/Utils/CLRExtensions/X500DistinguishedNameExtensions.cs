using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SysadminsLV.PKI.Utils.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X500DistinguishedName"/> class.
    /// </summary>
    public static class X500DistinguishedNameExtensions {
        /// <summary>
        /// Converts an <see cref="X500DistinguishedName"/> instance in to a collection of individual
        /// RDN attributes.
        /// </summary>
        /// <param name="name">Existing instance of <strong>X500DistinguishedName</strong>.</param>
        /// <returns>A collection of RDN attributes.</returns>
        public static X500RdnAttributeCollection GetRdnAttributes(this X500DistinguishedName name) {
            if (name == null) {
                throw new ArgumentNullException(nameof(name));
            }
            if (name.RawData == null || name.RawData.Length == 0) {
                return null;
            }

            var retValue = new X500RdnAttributeCollection();
            retValue.Decode(name.RawData);
            
            return retValue;
        }

        /// <inheritdoc cref="AsnEncodedData.Format(Boolean)"/>
        public static String FormatReverse(this X500DistinguishedName name, Boolean multiLine) {
            if (name == null) {
                return String.Empty;
            }

            var sb = new StringBuilder();
            X500RdnAttributeCollection rdnAttributes = name.GetRdnAttributes();
            if (rdnAttributes.Any()) {
                if (multiLine) {
                    foreach (X500RdnAttribute rdn in rdnAttributes) {
                        sb.AppendLine(rdn.Format(false));
                    }
                } else {
                    sb.Append(String.Join(", ", rdnAttributes.Select(x => x.Format(false))));
                }
            } else {
                sb.Append("EMPTY");
            }
            

            return sb.ToString().TrimEnd();
        }
    }
}
