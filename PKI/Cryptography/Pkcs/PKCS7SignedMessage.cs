using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509CertificateRequests;
using System.Security.Cryptography.X509Certificates;
using PKI.ManagedAPI;
using PKI.Structs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Cryptography.Pkcs {
    /// <summary>
    /// Represents a PKCS#7 message syntax format.
    /// </summary>
    [Obsolete("Use SignedPkcs7 class or its inheritors instead.", true), SecurityCritical]
    public class PKCS7SignedMessage {
        readonly List<X509Attribute> _attributes          = new();
        readonly List<Oid> _digestAlgs                    = new();
        readonly List<X509CRL2> _crls                     = new();
        readonly X509Certificate2Collection _certificates = new();
        readonly List<X509CertificateRequest> _requests   = new();
        readonly List<PkcsSignerInfo> _signerInfos        = new();

        /// <param name="path">Specifies the path to a file that contains either binary or Base64-encoded PKCS#7 message.</param>
        /// <exception cref="ArgumentException"><strong>path</strong> parameter is null or empty string.</exception>
        /// <exception cref="ArgumentNullException">Specified file does not exist.</exception>
        public PKCS7SignedMessage(String path) {
            if (String.IsNullOrEmpty(path)) { throw new ArgumentNullException(nameof(path)); }
            if (!File.Exists(path)) { throw new ArgumentException("The system cannot find the file specified."); }
            m_initialize(Crypt32Managed.CryptFileToBinary(path));
        }
        /// <param name="message">ASN.1-encoded byte array that contains a PKCS#7/CMS message.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
        /// <exception cref="InvalidDataException">The data in the <strong>rawData</strong> parameter is not valid PKCS#7/CMS message.</exception>
        public PKCS7SignedMessage(Byte[] message) {
            if (message == null) { throw new ArgumentNullException(nameof(message)); }
            m_initialize(message);
        }

        /// <summary>
        /// Gets the version of the CMS/PKCS #7 message.
        /// </summary>
        public Int32 Version { get; set; }
        /// <summary>
        /// Gets an array of hashing algorithms.
        /// </summary>
        public OidCollection DigestAlgorithms {
            get {
                if (_digestAlgs == null) { return null; }
                var oids = new OidCollection();
                foreach (Oid oid in _digestAlgs) {
                    oids.Add(oid);
                }
                return oids;
            }
        }
        /// <summary>
        /// Gets the type of the inner content message. Depending on a content type, different object types are
        /// stored in the <see cref="Content"/> property.
        /// </summary>
        /// <remarks>
        /// The following table provides a mapping between content type and object type stored in the
        /// <see cref="Content"/> property:
        /// <list type="table">
        ///		<listheader>
        ///			<term>Content type</term>
        ///			<description>Object type</description>
        ///		</listheader>
        ///		<item>
        ///			<term>1.3.6.1.5.5.7.12.2 (CMC data)</term>
        ///			<description>X509CertificateRequest[]</description>
        ///		</item>
        ///		<item>
        ///			<term>other</term>
        ///			<description>Byte[]</description>
        ///		</item>
        /// </list>
        /// </remarks>
        public Oid ContentType { get; private set; }
        /// <summary>
        /// Gets an object that represents inner content. For the value type mapping see remarks for
        /// <see cref="ContentType"/> property.
        /// </summary>
        public Object Content { get; private set; }
        /// <summary>
        /// Gets a collection of certificates contained in the message.
        /// </summary>
        public X509Certificate2Collection Certificates => new(_certificates);
        /// <summary>
        /// Gets an array of certificate revocation lists contained in the message.
        /// </summary>
        public X509CRL2[] RevocationLists => _crls.ToArray();
        /// <summary>
        /// Gets a collection of tagged attributes associated with the message.
        /// </summary>
        public X509AttributeCollection Attributes => new(_attributes.ToArray());
        /// <summary>
        /// Gets an array of signer information that were used to sign the message.
        /// </summary>
        public PkcsSignerInfo[] SignerInfos => _signerInfos.ToArray();
        /// <summary>
        /// Gets 
        /// </summary>
        public Byte[] RawData { get; private set; }

        void m_initialize(Byte[] message) {
            RawData = message;
            var info = new ContentInfo2(RawData);
            getSequence(info);
        }
        void getSequence(ContentInfo2 info) {
            UInt32 pcbStructInfo = 0;
            if (!Crypt32.CryptDecodeObject(1, Wincrypt.X509_SEQUENCE_OF_ANY, info.RawData, (UInt32)info.RawData.Length, 0, IntPtr.Zero, ref pcbStructInfo)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
            try {
                Crypt32.CryptDecodeObject(1, Wincrypt.X509_SEQUENCE_OF_ANY, info.RawData, (UInt32)info.RawData.Length, 0, pvStructInfo, ref pcbStructInfo);
                var sequence = (Wincrypt.CRYPTOAPI_BLOB)Marshal.PtrToStructure(pvStructInfo, typeof(Wincrypt.CRYPTOAPI_BLOB));
                if (sequence.cbData == 0) { return; }
                UnrollPkcs7(sequence);
            } finally {
                Marshal.FreeHGlobal(pvStructInfo);
            }
        }
        void UnrollPkcs7(Wincrypt.CRYPTOAPI_BLOB sequence) {
            Int32 size = Marshal.SizeOf(typeof(Wincrypt.CRYPTOAPI_BLOB));
            IntPtr pValue = sequence.pbData;
            for (var index = 0; index < sequence.cbData; index++) {
                var blob = (Wincrypt.CRYPTOAPI_BLOB)Marshal.PtrToStructure(pValue, typeof(Wincrypt.CRYPTOAPI_BLOB));
                switch (index) {
                    case 0:
                        decodeVersion(blob);
                        break;
                    case 1:
                        decodeAlgorithms(blob);
                        break;
                    case 2:
                        switchInnerType(blob);
                        break;
                    default: {
                        Byte[] nextTag = new Byte[1];
                        Marshal.Copy(blob.pbData, nextTag, 0, 1);
                        switch (nextTag[0]) {
                            case 160:
                                decodeCerts(blob);
                                break;
                            case 161:
                                decodeCrls(blob);
                                break;
                            case 49:
                                decodeSignerInfos(blob);
                                break;
                        }
                    }
                        break;
                }
                pValue += size;
            }
        }
        void decodeVersion(Wincrypt.CRYPTOAPI_BLOB blob) {
            Byte[] rawData = new Byte[blob.cbData];
            Marshal.Copy(blob.pbData, rawData, 0, (Int32)blob.cbData);
            Version = (Int32)Asn1Utils.DecodeInteger(rawData);
        }
        void decodeAlgorithms(Wincrypt.CRYPTOAPI_BLOB blob) {
            if (blob.cbData == 0) { return; }
            Byte[] rawData = new Byte[blob.cbData];
            Marshal.Copy(blob.pbData, rawData, 0, (Int32)blob.cbData);
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != 49) { throw new Asn1InvalidTagException(asn.Offset); }
            asn.MoveNext();
            do {
                _digestAlgs.Add(new AlgorithmIdentifier(asn.GetTagRawData()).AlgorithmId);
            } while (asn.MoveNextCurrentLevel());
        }
        void switchInnerType(Wincrypt.CRYPTOAPI_BLOB blob) {
            var info = new ContentInfo2(blob);
            ContentType = info.ContentType;
            switch (info.ContentType.Value) {
                case "1.3.6.1.5.5.7.12.2":
                    decodeCMC(info.RawData);
                    break;
                default:
                    Content = info.RawData;
                    break;
            }
        }
        void decodeCMC(Byte[] contentBytes) {
            var asn = new Asn1Reader(contentBytes);
            asn.MoveNext();
            UInt32 pcbStructInfo = 0;
            if (!Crypt32.CryptDecodeObject(1, Wincrypt.CMC_DATA, asn.GetTagRawData(), (UInt32)asn.TagLength, 0, IntPtr.Zero, ref pcbStructInfo)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            IntPtr pvStructInfo = Marshal.AllocHGlobal((Int32)pcbStructInfo);
            try {
                Crypt32.CryptDecodeObject(1, Wincrypt.CMC_DATA, asn.GetTagRawData(), (UInt32)asn.TagLength, 0, pvStructInfo, ref pcbStructInfo);
                var cmc = (Wincrypt.CMC_DATA_INFO)Marshal.PtrToStructure(pvStructInfo, typeof(Wincrypt.CMC_DATA_INFO));
                decodeAttributes(cmc.rgTaggedAttribute, cmc.cTaggedAttribute);
                decodeRequest(cmc.rgTaggedRequest, cmc.cTaggedRequest);
                Content = _requests.ToArray();
            } finally {
                Marshal.FreeHGlobal(pvStructInfo);
            }
        }
        void decodeAttributes(IntPtr rgTaggedAttribute, UInt32 cTaggedAttribute) {
            if (cTaggedAttribute == 0) { return; }
            IntPtr rgValue = rgTaggedAttribute;
            Int32 size = Marshal.SizeOf(typeof(Wincrypt.CMC_TAGGED_ATTRIBUTE));
            for (var index = 0; index < cTaggedAttribute; index++) {
                var attr = (Wincrypt.CMC_TAGGED_ATTRIBUTE)Marshal.PtrToStructure(rgValue, typeof(Wincrypt.CMC_TAGGED_ATTRIBUTE));
                var attrvalue = (Wincrypt.CRYPTOAPI_BLOB)Marshal.PtrToStructure(attr.rgValue, typeof(Wincrypt.CRYPTOAPI_BLOB));
                Byte[] bytes = new Byte[attrvalue.cbData];
                Marshal.Copy(attrvalue.pbData, bytes, 0, (Int32)attrvalue.cbData);
                _attributes.Add(new X509Attribute(new Oid(attr.pszObjId), (Int32)attr.dwBodyPartID, bytes));
                rgValue += size;
            }
        }
        void decodeRequest(IntPtr rgTaggedRequest, UInt32 cTaggedRequest) {
            if (cTaggedRequest == 0) { return; }
            IntPtr rgValue = rgTaggedRequest;
            Int32 size = Marshal.SizeOf(typeof(Wincrypt.CMC_TAGGED_REQUEST));
            for (var index = 0; index < cTaggedRequest; index++) {
                var req = (Wincrypt.CMC_TAGGED_REQUEST)Marshal.PtrToStructure(rgValue, typeof(Wincrypt.CMC_TAGGED_REQUEST));
                var a = (Wincrypt.CMC_TAGGED_CERT_REQUEST)Marshal.PtrToStructure(req.pTaggedCertRequest, typeof(Wincrypt.CMC_TAGGED_CERT_REQUEST));
                if (a.SignedCertRequest.cbData == 0) { continue; }
                Byte[] reqBytes = new Byte[a.SignedCertRequest.cbData];
                Marshal.Copy(a.SignedCertRequest.pbData, reqBytes, 0, (Int32)a.SignedCertRequest.cbData);
                _requests.Add(new X509CertificateRequest(reqBytes));
                rgValue += size;
            }
        }
        // TODO
        //void decodeCmcContentInfo(IntPtr rgTaggedRequest, UInt32 cTaggedRequest) {

        //}
        //void decodeCmcOtherMsg(IntPtr rgTaggedRequest, UInt32 cTaggedRequest) {

        //}
        void decodeCerts(Wincrypt.CRYPTOAPI_BLOB blob) {
            if (blob.cbData == 0) { return; }
            Byte[] certBytes = new Byte[blob.cbData];
            Marshal.Copy(blob.pbData, certBytes, 0, certBytes.Length);
            var asn = new Asn1Reader(certBytes);
            asn.MoveNext();
            do {
                _certificates.Add(new X509Certificate2(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
        }
        void decodeCrls(Wincrypt.CRYPTOAPI_BLOB blob) {
            if (blob.cbData == 0) { return; }
            Byte[] crlBytes = new Byte[blob.cbData];
            Marshal.Copy(blob.pbData, crlBytes, 0, (Int32)blob.cbData);
            var asn = new Asn1Reader(crlBytes);
            asn.MoveNext();
            do {
                _crls.Add(new X509CRL2(asn.GetTagRawData()));
            } while (asn.MoveNextCurrentLevel());
        }
        void decodeSignerInfos(Wincrypt.CRYPTOAPI_BLOB blob) {
            if (blob.cbData == 0) { return; }
            Byte[] signerBytes = new Byte[blob.cbData];
            Marshal.Copy(blob.pbData, signerBytes, 0, signerBytes.Length);
            var asn = new Asn1Reader(signerBytes);
            asn.MoveNext();
            do {
                _signerInfos.Add(new PkcsSignerInfo(asn.GetTagRawData(), _certificates));
            } while (asn.MoveNextCurrentLevel());
        }
    }
}
