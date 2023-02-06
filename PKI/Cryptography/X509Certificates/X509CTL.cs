using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Security.Permissions;
using System.Text;
using PKI.ManagedAPI;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Win32;

namespace System.Security.Cryptography.X509Certificates {
    /// <summary>
    /// Represents a X.509 Certificate Trust List (CTL).
    /// </summary>
    [Obsolete("X509CTL is replaced with X509CertificateTrustList class.")]
    public class X509CTL : IDisposable {
        Wincrypt.CTL_INFO CTLInfo;
        readonly List<X509Extension> _listExtensions = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="X509CTL"/> class using the path to a CTL file. 
        /// </summary>
        /// <param name="path">The path to a CRL file.</param>
        public X509CTL(String path) {
            m_import(Crypt32Managed.CryptFileToBinary(path));
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="X509CTL"/> class defined from a sequence of bytes representing
        /// an X.509 certificate trust list.
        /// </summary>
        /// <param name="rawData">A byte array containing data from an X.509 CTL.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public X509CTL(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
            m_import(rawData);
        }

        /// <summary>
        /// Gets X.509 certificate trust list (<strong>CTL</strong>) version.
        /// </summary>
        public Int32 Version { get; private set; }
        /// <summary>
        /// Gets a collection of <strong>OIDs</strong> that represents intended usages of the certificate trust list.
        /// </summary>
        public OidCollection SubjectUsage { get; private set; }
        /// <summary>
        /// Gets a string that uniquely identifies the list. This member is used to augment the SubjectUsage and further specifies the list when desired.
        /// </summary>
        public String ListIdentifier { get; private set; }
        /// <summary>
        /// Gets a monotonically increasing number for each update of the <strong>CTL</strong>.
        /// </summary>
        public String SequenceNumber { get; private set; }
        /// <summary>
        /// Gets the issue date of this.
        /// </summary>
        public DateTime ThisUpdate { get; private set; }
        /// <summary>
        /// Indication of the date and time for the CTL's next available scheduled update.
        /// </summary>
        public DateTime NextUpdate { get; private set; }
        /// <summary>
        /// Gets the algorithm type of the <see cref="X509CTLEntry.Thumbprint">Thumbprint</see> in <see cref="X509CTLEntry"/> members of the
        /// <see cref="Entries"/> member array.
        /// </summary>
        public Oid SubjectAlgorithm { get; private set; }
        /// <summary>
        /// Gets a collection of <see cref="X509CTLEntry"/> elements.
        /// </summary>
        public X509CTLEntryCollection Entries { get; private set; }
        /// <summary>
        /// Gets a collection of <see cref="X509Extension">X509Extension</see> objects.
        /// </summary>
        /// <remarks><p>Version 1 CTLs do not support extensions and this property is always empty for them.</p>
        /// </remarks>
        public X509ExtensionCollection Extensions {
            get {
                if (_listExtensions.Count == 0) { return null; }
                var retValue = new X509ExtensionCollection();
                foreach (X509Extension item in _listExtensions) { retValue.Add(item); }
                return retValue;
            }
        }
        /// <summary>
        /// Gets a handle to a Microsoft Cryptographic API CTL context described by an unmanaged
        /// <strong>CTL_CONTEXT</strong> structure.
        /// </summary>
        public SafeCTLHandleContext Handle { get; private set; }
        /// <summary>
        /// Gets the raw data of a certificate trust list.
        /// </summary>
        public Byte[] RawData { get; private set; }

        void getCtlinfo() {
            var CTLContext = (Wincrypt.CTL_CONTEXT)Marshal.PtrToStructure(Handle.DangerousGetHandle(), typeof(Wincrypt.CTL_CONTEXT));
            CTLInfo = (Wincrypt.CTL_INFO)Marshal.PtrToStructure(CTLContext.pCtlInfo, typeof(Wincrypt.CTL_INFO));
            Version = (Int32)CTLInfo.dwVersion + 1;
        }
        void getUsages() {
            SubjectUsage = new OidCollection();
            if (CTLInfo.SubjectUsage.cUsageIdentifier > 0) {
                IntPtr rgpszUseageIdentifier = CTLInfo.SubjectUsage.rgpszUseageIdentifier;
                for (var index = 0; index < CTLInfo.SubjectUsage.cUsageIdentifier; index++) {
                    IntPtr pszOid = Marshal.ReadIntPtr(rgpszUseageIdentifier);
                    SubjectUsage.Add(new Oid(Marshal.PtrToStringAnsi(pszOid)));
                    rgpszUseageIdentifier = (IntPtr)((UInt64)rgpszUseageIdentifier + (UInt32)Marshal.SizeOf(typeof(Wincrypt.CTL_USAGE)));
                }
            }
        }
        void getIdentifier() {
            if (CTLInfo.ListIdentifier.cbData != 0) {
                Byte[] rawString = new Byte[CTLInfo.ListIdentifier.cbData];
                Marshal.Copy(CTLInfo.ListIdentifier.pbData, rawString, 0, rawString.Length);
                GenericArray.ReverseOrder(ref rawString);
                rawString = Asn1Utils.Encode(rawString, (Byte)Asn1Type.BMPString);
                ListIdentifier = Asn1Utils.DecodeBMPString(rawString);
            }
        }
        void getSerial() {
            var SB = new StringBuilder();
            Byte[] seqnumber = new Byte[CTLInfo.SequenceNumber.cbData];
            Marshal.Copy(CTLInfo.SequenceNumber.pbData, seqnumber, 0, seqnumber.Length);
            Array.Reverse(seqnumber);
            foreach (Byte item in seqnumber) { SB.Append($"{item:x2}"); }
            SequenceNumber = SB.ToString();
        }
        void getCtlEntries() {
            if (CTLInfo.cCTLEntry > 0) {
                Entries = new X509CTLEntryCollection();
                IntPtr rgCTLEntry = CTLInfo.rgCTLEntry;
                for (var index = 0; index < CTLInfo.cCTLEntry; index++) {
                    var SB = new StringBuilder();
                    var attributes = new Pkcs9AttributeObjectCollection();

                    var CTLEntry = (Wincrypt.CTL_ENTRY)Marshal.PtrToStructure(rgCTLEntry, typeof(Wincrypt.CTL_ENTRY));
                    Byte[] bytes = new Byte[CTLEntry.SubjectIdentifier.cbData];
                    Marshal.Copy(CTLEntry.SubjectIdentifier.pbData, bytes, 0, bytes.Length);
                    foreach (Byte item in bytes) { SB.Append($"{item:X2}"); }
                    String thumbprint = SB.ToString();
                    if (CTLEntry.cAttribute > 0) {
                        IntPtr rgAttribute = CTLEntry.rgAttribute;
                        for (var indexx = 0; indexx < CTLEntry.cAttribute; indexx++) {
                            var attrib = (Wincrypt.CRYPT_ATTRIBUTE)Marshal.PtrToStructure(rgAttribute, typeof(Wincrypt.CRYPT_ATTRIBUTE));
                            var pszOid = new Oid(attrib.pszObjId);
                            var blob = (Wincrypt.CRYPTOAPI_BLOB)Marshal.PtrToStructure(attrib.rgValue, typeof(Wincrypt.CRYPTOAPI_BLOB));
                            bytes = new Byte[blob.cbData];
                            Marshal.Copy(blob.pbData, bytes, 0, bytes.Length);
                            attributes.Add(new Pkcs9AttributeObject(pszOid, bytes));
                            rgAttribute = (IntPtr)((UInt64)rgAttribute + (UInt32)Marshal.SizeOf(typeof(Wincrypt.CRYPT_ATTRIBUTE)));
                        }
                    }
                    Entries.Add(new X509CTLEntry(thumbprint, attributes));
                    rgCTLEntry = (IntPtr)((UInt64)rgCTLEntry + (UInt32)Marshal.SizeOf(typeof(Wincrypt.CTL_ENTRY)));
                }
            }
        }
        void getExtensions() {
            if (CTLInfo.cExtension > 0) {
                var extstruct = new Wincrypt.CERT_EXTENSIONS {
                    rgExtension = CTLInfo.rgExtension,
                    cExtension = CTLInfo.cExtension
                };
                _listExtensions.AddRange(CryptographyUtils.DecodeX509ExtensionCollection2(extstruct));
            }
        }
        void getAlgorithm() {
            SubjectAlgorithm = new Oid(CTLInfo.SubjectAlgorithm.pszObjId);
        }
        void m_import(Byte[] rawData) {
            RawData = rawData;
            Dispose();
            GetSafeContext();
            getCtlinfo();
            getUsages();
            getIdentifier();
            getSerial();
            ThisUpdate = DateTime.FromFileTime(CTLInfo.ThisUpdate);
            NextUpdate = DateTime.FromFileTime(CTLInfo.NextUpdate);
            getCtlEntries();
            getExtensions();
            getAlgorithm();
        }

        #region generation functions
        void set_certs(X509Certificate2Collection certs) {
            List<Wincrypt.CTL_ENTRY> entries = (from X509Certificate2 cert in certs where !cert.Handle.Equals(IntPtr.Zero) select create_ctlentry(cert.Handle, cert.Thumbprint)).ToList();
            CTLInfo = new Wincrypt.CTL_INFO {
                cCTLEntry = (UInt32)certs.Count,
                rgCTLEntry = create_ctlentries(entries)
            };
        }
        static IntPtr create_ctlentries(IEnumerable<Wincrypt.CTL_ENTRY> entries) {
            Int32 rgCTLEntrySize = Marshal.SizeOf(typeof(Wincrypt.CTL_ENTRY));
            IntPtr rgCTLEntry = Marshal.AllocHGlobal(rgCTLEntrySize);
            IntPtr ptr = rgCTLEntry;
            foreach (Wincrypt.CTL_ENTRY entry in entries) {
                Marshal.StructureToPtr(entry, ptr, true);
                ptr = (IntPtr)((Int32)ptr + rgCTLEntrySize);
            }
            return rgCTLEntry;
        }
        static Wincrypt.CTL_ENTRY create_ctlentry(IntPtr handle, String thumbprint) {
            var entry = new Wincrypt.CTL_ENTRY {
                SubjectIdentifier = {
                    pbData = get_thumbptr(thumbprint),
                    cbData = (UInt32)(thumbprint.Length / 2)
                }
            };

            List<UInt32> ids = new List<UInt32>();
            var end = false;
            do {
                UInt32 retn = Crypt32.CertEnumCertificateContextProperties(handle, 0);
                if (retn == 0) { end = true; } else { ids.Add(retn); }
            } while (!end);
            if (ids.Count > 0) {
                entry.cAttribute = (UInt32)ids.Count;
                entry.rgAttribute = create_attributes(handle, ids);
            }
            return entry;
        }
        static IntPtr create_attributes(IntPtr handle, ICollection ids) {
            Int32 rgAttributeSize = Marshal.SizeOf(typeof(Wincrypt.CRYPT_ATTRIBUTE));
            IntPtr rgAttributes = Marshal.AllocHGlobal(Marshal.SizeOf(rgAttributeSize * ids.Count));
            IntPtr ptr = rgAttributes;
            foreach (Wincrypt.CRYPT_ATTRIBUTE attrib in from UInt32 id in ids select create_attribute(handle, id)) {
                Marshal.StructureToPtr(attrib, ptr, true);
                ptr = (IntPtr)((Int32)ptr + rgAttributeSize);
            }
            return rgAttributes;
        }
        static Wincrypt.CRYPT_ATTRIBUTE create_attribute(IntPtr handle, UInt32 propId) {
            UInt32 pcbData = 0;
            var attrib = new Wincrypt.CRYPT_ATTRIBUTE();
            if (Crypt32.CertGetCertificateContextProperty(handle, propId, IntPtr.Zero, ref pcbData)) {
                attrib.rgValue = Marshal.AllocHGlobal((Int32)pcbData);
                attrib.pszObjId = "1.3.6.1.4.1.311.10.11." + propId;
                attrib.cValue = pcbData;
                Crypt32.CertGetCertificateContextProperty(handle, propId, attrib.rgValue, ref pcbData);
            } else {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return attrib;
        }
        static IntPtr get_thumbptr(String thumbprint) {
            Byte[] thBytes = AsnFormatter.StringToBinary(thumbprint, EncodingType.HexAny);
            IntPtr thumbPtr = Marshal.AllocHGlobal(thBytes.Length);
            Marshal.Copy(thBytes, 0, thumbPtr, thBytes.Length);
            return thumbPtr;
        }
        #endregion

        /// <summary>
        /// Resets the state of an X509CTL.
        /// </summary>
        /// <remarks>This method can be used to reset the state of the CTL. It also frees any resources associated with the CTL.</remarks>
        public void Reset() {
            Dispose();
            Version = 0;
            SubjectUsage = null;
            SequenceNumber = null;
            ThisUpdate = new DateTime();
            SubjectAlgorithm = null;
            Entries.Clear();
            Entries = null;
            _listExtensions.Clear();
            RawData = null;
        }
        /// <summary>
        ///     Gets a <see cref="SafeCTLHandleContext" /> for the X509 certificate revocation list. The caller of this
        ///     method owns the returned safe handle, and should dispose of it when they no longer need it. 
        ///     This handle can be used independently of the lifetime of the original X509 certificate revocation list.
        /// </summary>
        /// <returns>Safe handle to a current CTL instance.</returns>
        /// <permission cref="SecurityPermission">
        ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this method
        /// </permission>
        public void GetSafeContext() {
            if (Handle.IsInvalid || Handle.IsClosed) {
                Handle = Crypt32.CertCreateCTLContext(65537, RawData, (UInt32)RawData.Length);
                GC.KeepAlive(this);
            }
        }
        /// <summary>
        /// Displays a X.509 Certificate Revocation List UI dialog.
        /// </summary>
        public void ShowUI() {
            var mustRelease = false;
            if (Handle.IsInvalid || Handle.IsClosed) {
                mustRelease = true;
                GetSafeContext();
            }
            CryptUI.CryptUIDlgViewContext(3, Handle.DangerousGetHandle(), IntPtr.Zero, "Certificate Trust List", 0, 0);
            if (mustRelease) {
                Dispose();
            }
        }

        #region IDisposable
        void Dispose(Boolean disposing) {
            if (disposing) {
                Handle.Dispose();
            }
        }
        /// <inheritdoc cref="IDisposable.Dispose"/>
        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        /// <inheritdoc />
        ~X509CTL() {
            Dispose(false);
        }
        #endregion
    }
}
