using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using PKI.Exceptions;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Win32;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Defines the <strong>id-pkix-ocsp-service-locator</strong> extension (defined in <see href="http://tools.ietf.org/html/rfc2560">RFC2560</see>).
    /// This class cannot be inherited.
    /// </summary>
    public sealed class X509ServiceLocatorExtension : X509Extension {
        Byte[] AIARaw;
        readonly Oid _oid = new Oid(X509ExtensionOid.ServiceLocator, "OCSP Service Locator");
        
        /// <summary>
        /// Initializes a new instance of the <strong>X509ServiceLocatorExtension</strong> class.
        /// </summary>
        /// <param name="cert">An <see cref="X509Certificate2"/> object from which to construct the extension.</param>
        public X509ServiceLocatorExtension(X509Certificate2 cert) {
            if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
            if (cert.Handle.Equals(IntPtr.Zero)) { throw new UninitializedObjectException(); }
            m_initialize(cert);
        }

        /// <param name="value">The encoded data to use to create the extension.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        public X509ServiceLocatorExtension(AsnEncodedData value, Boolean critical)
            : base(new Oid(X509ExtensionOid.ServiceLocator, "OCSP Service Locator"), value.RawData, critical) {
            m_decode(value.RawData);
        }

        /// <summary>
        /// Gets issuer X.500 distinguished name.
        /// </summary>
        public String IssuerName { get; private set; }

        /// <summary>
        /// Gets an array of URLs contained in <strong>Authority Information Access</strong> extension.
        /// </summary>
        public String[] AuthorityInformationAccess { get; private set; }

        void m_initialize(X509Certificate2 cert) {
            List<Byte> rawData = new List<Byte>();
            rawData.AddRange(cert.IssuerName.RawData);
            if (cert.Extensions.Count > 0) {
                X509Extension ext = cert.Extensions[X509ExtensionOid.AuthorityInformationAccess];
                if (ext != null) {
                    AIARaw = ext.RawData;
                    rawData.AddRange(ext.RawData);
                    m_extracturls(cert);
                }
            }
            rawData = new List<Byte>(Asn1Utils.Encode(rawData.ToArray(), 48));
            IssuerName = cert.Issuer;
            Critical = false;
            Oid = _oid;
            RawData = rawData.ToArray();
        }
        void m_extracturls(X509Certificate2 cert) {
            List<String> urls = new List<String>();
            foreach (UInt32 extid in new [] { 1, 13 }) {
                UInt32 pcbUrlArray = 0;
                UInt32 pcbUrlInfo = 0;
                if (Cryptnet.CryptGetObjectUrl(extid, cert.Handle, 2, null, ref pcbUrlArray, IntPtr.Zero, ref pcbUrlInfo, 0)) {
                    Byte[] pUrlArray = new Byte[pcbUrlArray];
                    IntPtr pUrlInfo = Marshal.AllocHGlobal((Int32)pcbUrlInfo);
                    Cryptnet.CryptGetObjectUrl(extid, cert.Handle, 2, pUrlArray, ref pcbUrlArray, pUrlInfo, ref pcbUrlInfo, 0);
                    String URL = CryptographyUtils.EncodeDerString(pUrlArray);
                    String[] delimeter = new String[1];
                    delimeter[0] = "\0";
                    String[] splitArray = URL.Split(delimeter, StringSplitOptions.RemoveEmptyEntries);
                    switch (extid) {
                        case 1: urls.AddRange(splitArray.Skip(3).Take(splitArray.Length - 1)); break;
                            //urls.AddRange(GenericArray.GetSubArray(splitArray, 3, splitArray.Length - 1)); break;
                        case 13: urls.AddRange(splitArray.Skip(3).Take(splitArray.Length - 1)); break;
                            //urls.AddRange(GenericArray.GetSubArray(splitArray, 3, splitArray.Length - 1)); break;
                    }
                    Marshal.FreeHGlobal(pUrlInfo);
                }
            }
            AuthorityInformationAccess = urls.ToArray();
        }
        void m_decode(Byte[] rawData) {
            //TODO
        }

        /// <summary>
        /// Returns a formatted version of the Abstract Syntax Notation One (ASN.1)-encoded data as a string.
        /// </summary>
        /// <param name="multiLine"><strong>True</strong> if the return string should contain carriage returns; otherwise, <strong>False</strong>.</param>
        /// <returns>A formatted string that represents the Abstract Syntax Notation One (ASN.1)-encoded data.</returns>
        public override String Format(Boolean multiLine) {
            StringBuilder SB = new StringBuilder();
            SB.Append("[0]Certificate issuer: ");
            if (multiLine) { SB.Append(Environment.NewLine + "     "); }
            SB.Append(IssuerName);
            if (multiLine) { SB.Append(Environment.NewLine); }
            if (AIARaw.Length > 1) {
                if (!multiLine) { SB.Append(", "); }
                X509Extension aia = new X509Extension(new Oid(X509ExtensionOid.AuthorityInformationAccess), AIARaw, false);
                SB.Append(aia.Format(multiLine));
            }
            return SB.ToString();
        }
    }
}