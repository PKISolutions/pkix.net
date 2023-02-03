using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PKI.Structs {
    public static class Wincrypt {
        #region enums
        // CryptGetProvParam flags 
        internal const UInt32 CRYPT_FIRST    = 1;
        internal const UInt32 CRYPT_NEXT     = 2;
        internal const UInt32 PP_ENUMALGS_EX = 22;

        // CrypFindOIDInfo find type
        internal const UInt32 CRYPT_OID_INFO_OID_KEY           = 1;
        internal const UInt32 CRYPT_OID_INFO_NAME_KEY          = 2;
        internal const UInt32 CRYPT_OID_INFO_ALGID_KEY         = 3;
        internal const UInt32 CRYPT_OID_INFO_SIGN_KEY          = 4;
        internal const UInt32 CRYPT_OID_INFO_CNG_ALGID_KEY     = 5;
        internal const UInt32 CRYPT_OID_INFO_CNG_SIGN_KEY      = 6;
        internal const UInt32 CRYPT_OID_DISABLE_SEARCH_DS_FLAG = 0x80000000;

        // dwFlags definitions for CryptAcquireContext
        internal const UInt32 CRYPT_VERIFYCONTEXT  = 0xF0000000;
        internal const UInt32 CRYPT_NEWKEYSET      = 0x00000008;
        internal const UInt32 CRYPT_DELETEKEYSET   = 0x00000010;
        internal const UInt32 CRYPT_MACHINE_KEYSET = 0x00000020;
        internal const UInt32 CRYPT_SILENT         = 0x00000040;
        internal const UInt32 CRYPT_USER_KEYSET    = 0x00001000;

        // dwFlags for CryptAcquireCertificatePrivateKey
        internal const UInt32 CRYPT_ACQUIRE_CACHE_FLAG             = 0x00000001;
        internal const UInt32 CRYPT_ACQUIRE_USE_PROV_INFO_FLAG     = 0x00000002;
        internal const UInt32 CRYPT_ACQUIRE_COMPARE_KEY_FLAG       = 0x00000004;
        internal const UInt32 CRYPT_ACQUIRE_NO_HEALING             = 0x00000008;
        internal const UInt32 CRYPT_ACQUIRE_SILENT_FLAG            = 0x00000040;
        internal const UInt32 CRYPT_ACQUIRE_NCRYPT_KEY_FLAGS_MASK  = 0x00070000;
        internal const UInt32 CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  = 0x00010000;
        internal const UInt32 CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000;
        internal const UInt32 CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   = 0x00040000;

        // lpszStructType types for CryptDecodeObject and CryptEncodeObject
        internal const UInt32 X509_CERT                      = 1;
        internal const UInt32 X509_CERT_REQUEST_TO_BE_SIGNED = 4;
        internal const UInt32 X509_EXTENSIONS                = 5;
        internal const UInt32 X509_NAME_VALUE                = 6;
        internal const UInt32 X509_BITS                      = 26;
        internal const UInt32 PKCS_CONTENT_INFO              = 33;
        internal const UInt32 X509_SEQUENCE_OF_ANY           = 34;
        internal const UInt32 CMC_DATA                       = 59;
        internal const UInt32 X509_ALGORITHM_IDENTIFIER      = 74;
        internal const UInt32 PKCS7_SIGNER_INFO              = 500;
        internal const UInt32 CMS_SIGNER_INFO                = 501;
        internal const String szOID_CERT_EXTENSIONS          = "1.3.6.1.4.1.311.2.1.14";
        internal const String szOID_BASIC_CONSTRAINTS2       = "2.5.29.19";

        // pszUrlOid types for CryptGetObjectUrl
        internal const Int32 URL_OID_CERTIFICATE_ISSUER                  = 1;
        internal const Int32 URL_OID_CERTIFICATE_CRL_DIST_POINT          = 2;
        internal const Int32 URL_OID_CTL_ISSUER                          = 3;
        internal const Int32 URL_OID_CTL_NEXT_UPDATE                     = 4;
        internal const Int32 URL_OID_CRL_ISSUER                          = 5;
        internal const Int32 URL_OID_CERTIFICATE_FRESHEST_CRL            = 6;
        internal const Int32 URL_OID_CRL_FRESHEST_CRL                    = 7;
        internal const Int32 URL_OID_CROSS_CERT_DIST_POINT               = 8;
        internal const Int32 URL_OID_CERTIFICATE_OCSP                    = 9;
        internal const Int32 URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT = 10;
        internal const Int32 URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP = 11;
        internal const Int32 URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS      = 12;
        internal const Int32 URL_OID_CERTIFICATE_ONLY_OCSP               = 13;

        //dwObjectType for CryptQueryObject
        //-------------------------------------------------------------------------
        internal const Int32 CERT_QUERY_OBJECT_FILE = 0x00000001;
        internal const Int32 CERT_QUERY_OBJECT_BLOB = 0x00000002;

        // dwContentType types for CryptQueryObject
        internal const Int32 CERT_QUERY_CONTENT_CERT               = 1;
        internal const Int32 CERT_QUERY_CONTENT_CTL                = 2;
        internal const Int32 CERT_QUERY_CONTENT_CRL                = 3;
        internal const Int32 CERT_QUERY_CONTENT_SERIALIZED_STORE   = 4;
        internal const Int32 CERT_QUERY_CONTENT_SERIALIZED_CERT    = 5;
        internal const Int32 CERT_QUERY_CONTENT_SERIALIZED_CTL     = 6;
        internal const Int32 CERT_QUERY_CONTENT_SERIALIZED_CRL     = 7;
        internal const Int32 CERT_QUERY_CONTENT_PKCS7_SIGNED       = 8;
        internal const Int32 CERT_QUERY_CONTENT_PKCS7_UNSIGNED     = 9;
        internal const Int32 CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10;
        internal const Int32 CERT_QUERY_CONTENT_PKCS10             = 11;
        internal const Int32 CERT_QUERY_CONTENT_PFX                = 12;
        internal const Int32 CERT_QUERY_CONTENT_CERT_PAIR          = 13;
        internal const Int32 CERT_QUERY_CONTENT_PFX_AND_LOAD       = 14;

        // dwExpectedConentTypeFlags for CryptQueryObject
        internal const Int32 CERT_QUERY_CONTENT_FLAG_CERT = 1 << CERT_QUERY_CONTENT_CERT;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_CTL = 1 << CERT_QUERY_CONTENT_CTL;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_CRL = 1 << CERT_QUERY_CONTENT_CRL;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = 1 << CERT_QUERY_CONTENT_SERIALIZED_STORE;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = 1 << CERT_QUERY_CONTENT_SERIALIZED_CERT;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = 1 << CERT_QUERY_CONTENT_SERIALIZED_CTL;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = 1 << CERT_QUERY_CONTENT_SERIALIZED_CRL;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 1 << CERT_QUERY_CONTENT_PKCS7_SIGNED;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = 1 << CERT_QUERY_CONTENT_PKCS7_UNSIGNED;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_PKCS10 = 1 << CERT_QUERY_CONTENT_PKCS10;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_PFX = 1 << CERT_QUERY_CONTENT_PFX;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_CERT_PAIR = 1 << CERT_QUERY_CONTENT_CERT_PAIR;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD = 1 << CERT_QUERY_CONTENT_PFX_AND_LOAD;
        internal const Int32 CERT_QUERY_CONTENT_FLAG_ALL =
            CERT_QUERY_CONTENT_CERT
            | CERT_QUERY_CONTENT_CTL
            | CERT_QUERY_CONTENT_CRL
            | CERT_QUERY_CONTENT_SERIALIZED_STORE
            | CERT_QUERY_CONTENT_SERIALIZED_CERT
            | CERT_QUERY_CONTENT_SERIALIZED_CTL
            | CERT_QUERY_CONTENT_SERIALIZED_CRL
            | CERT_QUERY_CONTENT_PKCS7_SIGNED
            | CERT_QUERY_CONTENT_PKCS7_UNSIGNED
            | CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED
            | CERT_QUERY_CONTENT_PKCS10
            | CERT_QUERY_CONTENT_PFX
            | CERT_QUERY_CONTENT_CERT_PAIR
            | CERT_QUERY_CONTENT_PFX_AND_LOAD;

        // dwFormatType for CryptQueryObject
        internal const Int32 CERT_QUERY_FORMAT_BINARY                = 1;
        internal const Int32 CERT_QUERY_FORMAT_BASE64_ENCODED        = 2;
        internal const Int32 CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3;

        //dwExpectedFormatTypeFlags for CryptQueryObject
        internal const Int32 CERT_QUERY_FORMAT_FLAG_BINARY = 1 << CERT_QUERY_FORMAT_BINARY;
        internal const Int32 CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = 1 << CERT_QUERY_FORMAT_BASE64_ENCODED;
        internal const Int32 CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = 1 << CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED;
        internal const Int32 CERT_QUERY_FORMAT_FLAG_ALL =
            CERT_QUERY_FORMAT_FLAG_BINARY
            | CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED
            | CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED;
        #endregion

        #region structs
        #region Generic structures
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CRYPTOAPI_BLOB {
            public UInt32 cbData;
            public IntPtr pbData;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CRYPT_ALGORITHM_IDENTIFIER {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public CRYPTOAPI_BLOB Parameters;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CRYPT_BIT_BLOB {
            public UInt32 cbData;
            public IntPtr pbData;
            public UInt32 cUnusedBits;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SystemTime {
            public Int16 Year;
            public Int16 Month;
            public Int16 DayOfWeek;
            public Int16 Day;
            public Int16 Hour;
            public Int16 Minute;
            public Int16 Second;
            public Int16 Milliseconds;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CRYPT_ATTRIBUTE {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public UInt32 cValue;
            public IntPtr rgValue;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ATTRIBUTES {
            public UInt32 cAttr;
            public IntPtr rgAttr;
        }
        #endregion

        #region CRLs
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CRL_CONTEXT {
            public UInt32 dwCertEncodingType;
            public IntPtr pbCrlEncoded;
            public UInt32 cbCrlEncoded;
            public IntPtr pCrlInfo;
            public IntPtr hCertStore;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CRL_INFO {
            public UInt32 dwVersion;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPTOAPI_BLOB Issuer;
            public Int64 ThisUpdate;
            public Int64 NextUpdate;
            public UInt32 cCRLEntry;
            public IntPtr rgCRLEntry;
            public UInt32 cExtension;
            public IntPtr rgExtension;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CRL_ENTRY {
            public CRYPTOAPI_BLOB SerialNumber;
            public Int64 RevocationDate;
            public UInt32 cExtension;
            public IntPtr rgExtension;
        }
        #endregion

        #region CTLs
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CTL_CONTEXT {
            internal UInt32 dwMsgAndCertEncodingType;
            internal IntPtr pbCtlEncoded;
            internal UInt32 cbCtlEncoded;
            internal IntPtr pCtlInfo;
            internal IntPtr hCertStore;
            internal IntPtr hCryptMsg;
            internal IntPtr pbCtlContent;
            internal UInt32 cbCtlContent;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CTL_INFO {
            internal UInt32 dwVersion;
            internal CTL_USAGE SubjectUsage;
            internal CRYPTOAPI_BLOB ListIdentifier;
            internal CRYPTOAPI_BLOB SequenceNumber;
            internal Int64 ThisUpdate;
            internal Int64 NextUpdate;
            internal CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
            internal UInt32 cCTLEntry;
            internal IntPtr rgCTLEntry;
            internal UInt32 cExtension;
            internal IntPtr rgExtension;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CTL_USAGE {
            internal UInt32 cUsageIdentifier;
            internal IntPtr rgpszUseageIdentifier;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CTL_ENTRY {
            internal CRYPTOAPI_BLOB SubjectIdentifier;
            internal UInt32 cAttribute;
            internal IntPtr rgAttribute;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct CTL_ANY_SUBJECT_INFO {
            internal CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
            internal CRYPTOAPI_BLOB SubjectIdentifier;
        }
        #endregion

        #region Extensions
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_EXTENSION {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public Boolean fCritical;
            public CRYPTOAPI_BLOB Value;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_EXTENSIONS {
            public UInt32 cExtension;
            public IntPtr rgExtension;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_BASIC_CONSTRAINTS2_INFO {
            public Boolean fCA;
            public Boolean fPathLenConstraint;
            public UInt32 dwPathLenConstraint;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_TEMPLATE_EXT {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public UInt32 dwMajorVersion;
            public Boolean fMinorVersion;
            public UInt32 dwMinorVersion;
        }
        #endregion

        #region OIDs
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct CRYPT_OID_INFO {
            public Int32 cbSize;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszOID;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pwszName;
            public OidGroup dwGroupId;
            public Int32 dwValue;
            public CRYPTOAPI_BLOB ExtraInfo;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pwszCNGAlgid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String pwszCNGExtraAlgid;
        }

        #endregion

        #region service providers
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CRYPT_KEY_PROV_INFO {
            public String pwszContainerName;
            public String pwszProvName;
            public Int32 dwProvType;
            public Int32 dwFlags;
            public Int32 cProvParam;
            public IntPtr rgProvParam;
            public X509KeySpecFlags dwKeySpec;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROV_ENUMALGS_EX {
            public UInt32 aiAlgid;
            public UInt32 dwDefaultLen;
            public UInt32 dwMinLen;
            public UInt32 dwMaxLen;
            public UInt32 dwProtocols;
            public UInt32 dwNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
            public String szName;
            public UInt32 dwLongNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
            public String szLongName;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_KEY_CONTEXT {
            public UInt32 cbSize;
            public IntPtr hCryptProv;
            public UInt32 dwKeySpec;
        }
        #endregion

        #region CMC
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMC_TAGGED_ATTRIBUTE {
            public UInt32 dwBodyPartID;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public UInt32 cValue;
            public IntPtr rgValue;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMC_TAGGED_CONTENT_INFO {
            public UInt32 dwBodyPartID;
            public UInt32 cbData;
            public IntPtr pbData;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMC_TAGGED_CERT_REQUEST {
            public UInt32 dwBodyPartID;
            public CRYPTOAPI_BLOB SignedCertRequest;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMC_TAGGED_REQUEST {
            //[FieldOffset(0)]
            public UInt32 dwTaggedRequestChoice;
            //[FieldOffset(4)]
            public IntPtr pTaggedCertRequest;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMSG_SIGNER_INFO {
            public UInt32 dwVersion;
            public CRYPTOAPI_BLOB Issuer;
            public CRYPTOAPI_BLOB SerialNumber;
            public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
            public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
            public CRYPTOAPI_BLOB EncryptedHash;
            public CRYPT_ATTRIBUTES AuthAttrs;
            public CRYPT_ATTRIBUTES UnauthAttrs;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMSG_CMS_SIGNER_INFO {
            public UInt32 dwVersion;
            public CERT_ID SignerId;
            public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
            public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
            public CRYPTOAPI_BLOB EncryptedHash;
            public CRYPT_ATTRIBUTES AuthAttrs;
            public CRYPT_ATTRIBUTES UnauthAttrs;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CMC_DATA_INFO {
            public UInt32 cTaggedAttribute;
            public IntPtr rgTaggedAttribute;
            public UInt32 cTaggedRequest;
            public IntPtr rgTaggedRequest;
            public UInt32 cTaggedContentInfo;
            public IntPtr rgTaggedContentInfo;
            public UInt32 cTaggedOtherMsg;
            public IntPtr rgTaggedOtherMsg;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CMSG_SIGNED_ENCODE_INFO {
            internal UInt32 cbSize;
            internal UInt32 cSigners;
            internal IntPtr rgSigners;
            internal UInt32 cCertEncoded;
            internal IntPtr rgCertEncoded;
            internal UInt32 cCrlEncoded;
            internal IntPtr rgCrlEncoded;
            internal UInt32 cAttrCertEncoded;
            internal IntPtr rgAttrCertEncoded;

        }
        #endregion

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_SIGNED_CONTENT_INFO {
            public CRYPTOAPI_BLOB ToBeSigned;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPT_BIT_BLOB Signature;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_PUBLIC_KEY_INFO {
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPT_BIT_BLOB PublicKey;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_ISSUER_SERIAL_NUMBER {
            public CRYPTOAPI_BLOB Issuer;
            public CRYPTOAPI_BLOB SerialNumber;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_ID {
            public UInt32 dwIdChoice;
            public CERT_ID_DATA pIdChoice;
        }
        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Auto)]
        public struct CERT_ID_DATA {
            [FieldOffset(0)]
            public CERT_ISSUER_SERIAL_NUMBER IssuerSerialNumber;
            [FieldOffset(0)]
            public CRYPTOAPI_BLOB KeyId;
            [FieldOffset(0)]
            public CRYPTOAPI_BLOB HashId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CERT_REQUEST_INFO {
            public UInt32 dwVersion;
            public CRYPTOAPI_BLOB Subject;
            public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
            public UInt32 cAttribute;
            public IntPtr rgAttribute;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_NAME_VALUE {
            public Int32 dwValueType;
            public CRYPTOAPI_BLOB Value;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_CONTENT_INFO {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;
            public UInt32 cbData;
            public IntPtr pbData;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct PUBKEYBLOBHEADERS {
            public Byte bType;
            public Byte bVersion;
            public Int16 reserved;
            public UInt32 aiKeyAlg;
            public UInt32 magic;
            public UInt32 bitlen;
            public UInt32 pubexp;
        }
    }
    #endregion
}
