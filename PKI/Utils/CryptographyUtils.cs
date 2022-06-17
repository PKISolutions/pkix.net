using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Structs;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace PKI.Utils {
    /// <summary>
    /// Contains helper methods for cryptographic objects.
    /// </summary>
    public static class CryptographyUtils {
        /// <summary>
        /// Converts default instance of <see cref="X509Extension"/> class to a specific extension implementation object.
        /// </summary>
        /// <param name="extension">Default instance of <see cref="X509Extension"/> class.</param>
        /// <returns>Explicit extension implementation if defined, otherwise, the same object is returned.</returns>
        public static X509Extension ConvertExtension(X509Extension extension) {
            AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
            switch (extension.Oid.Value) {
                case X509ExtensionOid.CAVersion:
                    return new X509CAVersionExtension(asndata, extension.Critical);
                case X509ExtensionOid.NextCRLPublish:
                    return new X509NextCRLPublishExtension(asndata, extension.Critical);
                case X509ExtensionOid.CertificateTemplate:
                    return new X509CertificateTemplateExtension(asndata, extension.Critical);
                case X509ExtensionOid.ApplicationPolicies:
                    return new X509ApplicationPoliciesExtension(asndata, extension.Critical);
                case X509ExtensionOid.ApplicationPolicyMappings:
                    return new X509ApplicationPolicyMappingsExtension(asndata);
                case X509ExtensionOid.ApplicationPolicyConstraints:
                    return new X509ApplicationPolicyConstraintsExtension(asndata);
                case X509ExtensionOid.PublishedCrlLocations:
                    return new X509PublishedCrlLocationsExtension(asndata, extension.Critical);
                case X509ExtensionOid.MsftSecurityIdentifier:
                    return new X509PublishedCrlLocationsExtension(asndata, extension.Critical);
                case X509ExtensionOid.AuthorityInformationAccess:
                    return new X509AuthorityInformationAccessExtension(asndata, extension.Critical);
                case X509ExtensionOid.OcspNonce:
                    return new X509NonceExtension(asndata, extension.Critical);
                case X509ExtensionOid.OcspCRLReference:
                    return new X509CRLReferenceExtension(asndata, extension.Critical);
                case X509ExtensionOid.ArchiveCutoff:
                    return new X509ArchiveCutoffExtension(asndata, extension.Critical);
                case X509ExtensionOid.ServiceLocator:
                    return new X509ServiceLocatorExtension(asndata, extension.Critical);
                case X509ExtensionOid.SubjectKeyIdentifier:
                    return new X509SubjectKeyIdentifierExtension(asndata, extension.Critical);
                case X509ExtensionOid.KeyUsage:
                    return new X509KeyUsageExtension(asndata, extension.Critical);
                case X509ExtensionOid.SubjectAlternativeNames:
                    return new X509SubjectAlternativeNamesExtension(asndata, extension.Critical);
                case X509ExtensionOid.IssuerAlternativeNames:
                    return new X509IssuerAlternativeNamesExtension(asndata, extension.Critical);
                case X509ExtensionOid.BasicConstraints:
                    return new X509BasicConstraintsExtension(asndata, extension.Critical);
                case X509ExtensionOid.CRLNumber:
                    return new X509CRLNumberExtension(asndata, extension.Critical);
                case X509ExtensionOid.IssuingDistributionPoint:
                    return new X509IssuingDistributionPointsExtension(asndata, extension.Critical);
                case X509ExtensionOid.NameConstraints:
                    return new X509NameConstraintsExtension(asndata);
                case X509ExtensionOid.CRLDistributionPoints:
                    return new X509CRLDistributionPointsExtension(asndata, extension.Critical);
                case X509ExtensionOid.CertificatePolicies:
                    return new X509CertificatePoliciesExtension(asndata, extension.Critical);
                case X509ExtensionOid.CertificatePolicyMappings:
                    return new X509CertificatePolicyMappingsExtension(asndata);
                case X509ExtensionOid.AuthorityKeyIdentifier:
                    return new X509AuthorityKeyIdentifierExtension(asndata, extension.Critical);
                case X509ExtensionOid.CertificatePolicyConstraints:
                    return new X509CertificatePolicyConstraintsExtension(asndata);
                case X509ExtensionOid.EnhancedKeyUsage:
                    return new X509EnhancedKeyUsageExtension(asndata, extension.Critical);
                case X509ExtensionOid.FreshestCRL:
                    return new X509FreshestCRLExtension(asndata, extension.Critical);
                default:
                    return extension;
            }
        }
        /// <summary>
        /// Converts a default instance of <see cref="X509Attribute"/> class to a specific atrribute implementation object. 
        /// </summary>
        /// <param name="attribute">Default instance of <see cref="X509Attribute"/> class.</param>
        /// <returns>Explicit attribute implementation if defined, otherwise, the same object is returned.</returns>
        public static X509Attribute ConvertAttribute(X509Attribute attribute) {
            // reserved for future use
            switch (attribute.Oid.Value) {
                default:
                    return attribute;
            }
        }
        /// <summary>
        /// Tests whether the running operating system supports Cryptography Next Generation (CNG).
        /// </summary>
        /// <returns>
        /// <strong>True</strong> if running operating system supports Cryptography Next Generation (CNG),
        /// otherwise <strong>False</strong>.
        /// </returns>
        /// <remarks>
        /// Windows operating systems starting with Windows Vista/Windows Server 2008 always return <strong>True</strong>.
        /// </remarks>
        public static Boolean TestCNGCompat() {
            return Environment.OSVersion.Version.Major >= 6;
        }
        /// <summary>
        /// Tests whether running operating system is compatible with OLE automation.
        /// </summary>
        /// <returns>
        /// <strong>True</strong> if running operating system is compatible with OLE automation,
        /// otherwise <strong>False</strong>.
        /// </returns>
        /// <remarks>
        /// Windows operating systems starting with Windows 8.1/Windows Server 2012 R2 return <strong>True</strong>.
        /// </remarks>
        public static Boolean TestOleCompat() {
            if (Environment.OSVersion.Version.Major < 6) { return false; }
            return Environment.OSVersion.Version.Major != 6 || Environment.OSVersion.Version.Minor >= 3;
        }
        /// <summary>
        /// Tests whether running operating system is compatible with ADCS Web Services.
        /// </summary>
        /// <returns>
        /// <strong>True</strong> if running operating system supports ADCS Web Services, otherwise <strong>False</strong>.
        /// </returns>
        /// <remarks>
        /// Windows operating systems starting with Windows7/Windows Server 2008 R2 return <strong>True</strong>.
        /// </remarks>
        public static Boolean TestCepCompat() {
            if (Environment.OSVersion.Version.Major < 6) { return false; }
            return Environment.OSVersion.Version.Major != 6 || Environment.OSVersion.Version.Minor != 0;
        }
        /// <summary>
        /// Releases all references to a Runtime Callable Wrapper (RCW) by setting its reference count to 0.
        /// </summary>
        /// <param name="ComObject">The RCW to be released.</param>
        public static void ReleaseCom(params Object[] ComObject) {
            if (ComObject == null) { return; }
            foreach (Object rcw in ComObject.Where(x => x != null)) {
                Marshal.FinalReleaseComObject(rcw);
            }
        }
        /// <summary>
        /// Converts unicode DER string to ASN.1-encoded byte array.
        /// </summary>
        /// <param name="str">Unicode string.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        /// <remarks>This method is necessary for ADCS interoperability.</remarks>
        public static Byte[] DecodeDerString(String str) {
            if (String.IsNullOrEmpty(str)) {
                throw new ArgumentNullException(nameof(str));
            }
            return Encoding.Unicode.GetBytes(str);
        }
        /// <summary>
        /// Converts ASN.1-encoded byte array to unicode string.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <returns>Unicode string.</returns>
        /// <remarks>This method is necessary for ADCS interoperability.</remarks>
        public static String EncodeDerString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            if (rawData.Length == 0) { throw new ArgumentException("The vlue is empty"); }
            List<Byte> rawBytes;
            if (rawData.Length % 2 > 0) {
                rawBytes = new List<Byte>(rawData.Length + 1);
                rawBytes.AddRange(rawData);
                rawBytes.Add(0);
            } else {
                rawBytes = new List<Byte>(rawData);
            }
            var sb = new StringBuilder(rawBytes.Count / 2);
            for (Int32 index = 0; index < rawBytes.Count; index += 2) {
                sb.Append(Convert.ToChar(rawBytes[index + 1] << 8 | rawBytes[index]));
            }
            return sb.ToString();
        }
        internal static IEnumerable<X509Extension> DecodeX509ExtensionCollection2(Wincrypt.CERT_EXTENSIONS extstruct) {
            return decode_extstruct(extstruct).ToArray();
        }

        static List<X509Extension> decode_extstruct(Wincrypt.CERT_EXTENSIONS extstruct) {
            List<X509Extension> extensions = new List<X509Extension>();
            if (extstruct.cExtension > 0) {
                IntPtr rgExtension = extstruct.rgExtension;
                for (UInt32 index = 0; index < extstruct.cExtension; index++) {
                    Wincrypt.CERT_EXTENSION ExtEntry = (Wincrypt.CERT_EXTENSION)Marshal.PtrToStructure(rgExtension, typeof(Wincrypt.CERT_EXTENSION));
                    Byte[] rawData = new Byte[ExtEntry.Value.cbData];
                    Marshal.Copy(ExtEntry.Value.pbData, rawData, 0, rawData.Length);
                    extensions.Add(ConvertExtension(new X509Extension(ExtEntry.pszObjId, rawData, ExtEntry.fCritical)));
                    rgExtension = rgExtension + Marshal.SizeOf(typeof(Wincrypt.CERT_EXTENSION));
                }
            }
            return extensions;
        }
    }
}
