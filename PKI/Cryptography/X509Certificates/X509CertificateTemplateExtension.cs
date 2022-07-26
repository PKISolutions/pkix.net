using System.ComponentModel;
using System.Runtime.InteropServices;
using PKI.Structs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.X509Certificates;
using SysadminsLV.PKI.Win32;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Defines Microsoft proprietary X.509 extension that represents certificate template extension used by
    /// Enterprise CA to store certificate template information. This extension is used by CAs and
    /// certificate autoenrollment to perform certificate-based renewals.
    /// </summary>
    public sealed class X509CertificateTemplateExtension : X509Extension {
        readonly Oid _oid = new Oid(X509ExtensionOid.CertTemplateInfoV2);

        internal X509CertificateTemplateExtension(Byte[] rawData, Boolean critical)
            : base(X509ExtensionOid.CertificateTemplate, rawData, critical) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_decode(rawData);
        }

        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificateTemplateExtension</strong> class.
        /// </summary>
        public X509CertificateTemplateExtension() { Oid = _oid; }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificateTemplateExtension</strong> class using an
        /// <see cref="AsnEncodedData"/> object and a value that identifies whether the extension is critical.
        /// </summary>
        /// <param name="templateInfo">The encoded data to use to create the extension.</param>
        /// <param name="critical"><strong>True</strong> if the extension is critical; otherwise, <strong>False</strong>.</param>
        /// <remarks>
        /// This constructor strictly checks whether the data in the <strong>templateInfo</strong> parameter is valid
        /// extension value.
        /// </remarks>
        public X509CertificateTemplateExtension(AsnEncodedData templateInfo, Boolean critical) :
            this(templateInfo.RawData, critical) { }
        /// <summary>
        /// Initializes a new instance of the <strong>X509CertificateTemplateExtension</strong> class by using
        /// certificate template information.
        /// </summary>
        /// <param name="templateOid">An OID of the certificate template.</param>
        /// <param name="majorVersion">A major version of the certificate template.</param>
        /// <param name="minorVersion">A minor version of the certificate template.</param>
        public X509CertificateTemplateExtension(Oid templateOid, Int32 majorVersion, Int32 minorVersion) {
            m_initialize(templateOid, majorVersion, minorVersion);
        }

        /// <summary>
        /// Gets certificate template OID value.
        /// </summary>
        public Oid TemplateOid { get; private set; }
        /// <summary>
        /// Gets certificate template major version.
        /// </summary>
        public Int32 MajorVersion { get; private set; }
        /// <summary>
        /// Gets certificate template minor version.
        /// </summary>
        public Int32 MinorVersion { get; private set; }

        void m_initialize(Oid oid, Int32 majorVersion, Int32 minorVersion) {
            Oid = _oid;
            Asn1Utils.EncodeObjectIdentifier(oid);
            var pvStructInfo = new Wincrypt.CERT_TEMPLATE_EXT {
                pszObjId = oid.Value,
                dwMajorVersion = (UInt32)majorVersion,
                dwMinorVersion = (UInt32)minorVersion,
                fMinorVersion = true
            };
            UInt32 pcbEncoded = 0;
            if (Crypt32.CryptEncodeObject(1, _oid.Value, ref pvStructInfo, null, ref pcbEncoded)) {
                RawData = new Byte[pcbEncoded];
                Crypt32.CryptEncodeObject(1, _oid.Value, ref pvStructInfo, RawData, ref pcbEncoded);
                TemplateOid = new Oid(pvStructInfo.pszObjId);
                MajorVersion = majorVersion;
                MinorVersion = minorVersion;
            } else {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        void m_decode(Byte[] rawData) {
            UInt32 pcbStructInfo = 0;
            if (Crypt32.CryptDecodeObject(1, _oid.Value, rawData, (UInt32)rawData.Length, 0, IntPtr.Zero, ref pcbStructInfo)) {
                IntPtr pbStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
                Crypt32.CryptDecodeObject(1, _oid.Value, rawData, (UInt32)rawData.Length, 0, pbStructInfo, ref pcbStructInfo);
                var structure = (Wincrypt.CERT_TEMPLATE_EXT)Marshal.PtrToStructure(pbStructInfo, typeof(Wincrypt.CERT_TEMPLATE_EXT));
                Marshal.FreeHGlobal(pbStructInfo);
                TemplateOid = new Oid(structure.pszObjId);
                MajorVersion = (Int32)structure.dwMajorVersion;
                MinorVersion = (Int32)structure.dwMinorVersion;
            } else {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
