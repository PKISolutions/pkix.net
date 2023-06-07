using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Win32;

/// <summary>
/// Contains only unmanaged function p/invoke definitions which are defined in <strong>Crypt32.dll</strong> library.
/// </summary>
static class Crypt32 {
    const String DLL_NAME = "Crypt32.dll";

    #region CRL functions
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern SafeCRLHandleContext CertCreateCRLContext(
        [In] UInt32 dwCertEncodingType,
        [In] Byte[] pbCrlEncoded,
        [In] UInt32 cbCrlEncoded
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern SafeCRLHandleContext CertDuplicateCRLContext(
        [In] IntPtr pCrlContext
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertFindCertificateInCRL(
        [In]            IntPtr pCert,
        [In]            IntPtr pCrlContext,
        [In]            UInt32 dwFlags,
        [In, Optional]  IntPtr pvReserved,
        [In, Out]ref IntPtr ppCrlEntry
    );
    [DllImport(DLL_NAME, SetLastError = true)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    public static extern Boolean CertFreeCRLContext(
        [In] IntPtr pCrlContext
    );
    #endregion
    #region CTL functions
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern SafeCTLHandleContext CertCreateCTLContext(
        [In]    UInt32 dwMsgAndCertEncodingType,
        [In]    Byte[] pbCtlEncoded,
        [In]    UInt32 cbCtlEncoded
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern SafeCTLHandleContext CertDuplicateCTLContext(
        [In] SafeCTLHandleContext pCtlContext
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release method")]
    [SuppressUnmanagedCodeSecurity]
    public static extern Boolean CertFreeCTLContext(
        [In]    IntPtr pCtlContext
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CertFindSubjectInCTL(
        [In]    UInt32 dwEncodingType,
        [In]    UInt32 dwSubjectType,
        [In]    IntPtr pvSubject,
        [In]    IntPtr pCtlContext,
        [In]    UInt32 dwFlags
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptMsgEncodeAndSignCTL(
        [In]            UInt32 dwMsgEncodingType,
        [In]            Wincrypt.CTL_INFO pCtlInfo,
        [In]            Wincrypt.CMSG_SIGNED_ENCODE_INFO pSignInfo,
        [In]            UInt32 dwFlags,
        [Out]           Byte[] pbEncoded,
        [In, Out]ref UInt32 pcbEncoded
    );

    #endregion

    [DllImport(DLL_NAME, SetLastError = true)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    public static extern Boolean CertFreeCertificateContext(
        [In] IntPtr pCertContext
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    static extern IntPtr CertCreateSelfSignCertificate(
        [In, Optional]  IntPtr phProv,
        [In]            Wincrypt.CRYPTOAPI_BLOB pSubjectIssuerBlob,
        [In]            UInt32 flags,
        [In, Optional]  Wincrypt.CRYPT_KEY_PROV_INFO pKeyProvInfo,
        [In, Optional]  IntPtr pSignatureAlgorithm,
        [In, Optional]  Wincrypt.SystemTime pStartTime,
        [In, Optional]  Wincrypt.SystemTime pEndTime,
        [Optional]      Wincrypt.CERT_EXTENSIONS pExtensions
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    static extern IntPtr CertFindExtension(
        [MarshalAs(UnmanagedType.LPStr)]
        [In] String pszObjId,
        [In] UInt32 cExtensions,
        [In] IntPtr rgExtensions
    );
    //[DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    //public static extern IntPtr CryptReleaseContext(
    //    [In] IntPtr hProv,
    //    [In] UInt32 dwFlags
    //);
    #region CryptDecodeObject functions
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptDecodeObject(
        [In]            UInt32 dwCertEncodingType,
        [MarshalAs(UnmanagedType.LPStr)]
        [In]            String  lpszStructType,
        [In]            IntPtr pbEncoded,
        [In]            UInt32 cbEncoded,
        [In]            UInt32 dwFlags,
        [Out]           IntPtr pvStructInfo,
        [In, Out]ref UInt32 pcbStructInfo
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptDecodeObject(
        [In]            UInt32 dwCertEncodingType,
        [MarshalAs(UnmanagedType.LPStr)]
        [In]            String lpszStructType,
        [In]            Byte[] pbEncoded,
        [In]            UInt32 cbEncoded,
        [In]            UInt32 dwFlags,
        [Out]           IntPtr pvStructInfo,
        [In, Out]ref UInt32 pcbStructInfo
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptDecodeObject(
        [In]            UInt32 dwCertEncodingType,
        [In]            UInt32 lpszStructType,
        [In]            IntPtr pbEncoded,
        [In]            UInt32 cbEncoded,
        [In]            UInt32 dwFlags,
        [Out]           IntPtr pvStructInfo,
        [In, Out]ref UInt32 pcbStructInfo
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptDecodeObject(
        [In]            UInt32 dwCertEncodingType,
        [In]            UInt32 lpszStructType,
        [In]            Byte[] pbEncoded,
        [In]            UInt32 cbEncoded,
        [In]            UInt32 dwFlags,
        [Out]           IntPtr pvStructInfo,
        [In, Out]ref UInt32 pcbStructInfo
    );
    #endregion
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptExportPublicKeyInfo(
        [In]            IntPtr phProv,
        [In]            UInt32 dwKeySpec,
        [In]            UInt32 dwCertEncodingType,
        [Out]           IntPtr pbInfo,
        [In, Out]ref UInt32 pcbInfo
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptHashPublicKeyInfo(
        [In]            IntPtr phProv,
        [In]            UInt32 Algid,
        [In]            UInt32 dwFlags,
        [In]            UInt32 dwCertEncodingType,
        [In]            IntPtr pInfo,
        [Out]           IntPtr pbComputedHash,
        [In, Out]ref UInt32 pcbComputedHash
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptMsgClose(
        [In] IntPtr hCryptMsg
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertCloseStore(
        [In] IntPtr hCertStore,
        [In] Int32 dwFlags
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptMsgGetParam(
        [In]     IntPtr hCryptMsg,
        [In]     Int32 dwParamType,
        [In]     Int32 dwIndex,
        [Out]    Byte[] pvData,
        [Out]out Int32 pcbData
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptQueryObject(
        [In]     Int32 dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)]
        [In]     String pvObject,
        [In]     Int32 dwExpectedContentTypeFlags,
        [In]     Int32 dwExpectedFormatTypeFlags,
        [In]     Int32 dwFlags,
        [Out]out Int32 pdwMsgAndCertEncodingType,
        [Out]out Int32 pdwContentType,
        [Out]out Int32 pdwFormatType,
        [Out]out IntPtr phCertStore,
        [Out]out IntPtr phMsg,
        [Out]out IntPtr ppvContext
    );
    #region OID functions
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CryptFindOIDInfo(
        [In] UInt32 dwKeyType,
        [In] IntPtr pvKey,
        [In] UInt32 dwGroupId
    );
    [SecurityCritical]
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptRegisterOIDInfo(
        [In] Wincrypt.CRYPT_OID_INFO pInfo,
        [In] UInt32 dwFlags
    );
    [SecurityCritical]
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptUnregisterOIDInfo(
        [In] Wincrypt.CRYPT_OID_INFO pInfo
    );
    #endregion
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptStringToBinary(
        [In] String pszString,
        [In] UInt32 cchString,
        [In] UInt32 dwFlags,
        [In] Byte[] pbBinary,
        [In, Out] ref UInt32 pcbBinary,
        [Out] UInt32 pdwSkip,
        [Out] UInt32 pdwFlags
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptBinaryToString(
        [In]            Byte[] pbBinary,
        [In]            UInt32 cbBinary,
        [In]            UInt32 dwFlags,
        StringBuilder pszString,
        [In, Out]ref UInt32 pcchString
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptAcquireCertificatePrivateKey(
        [In]            IntPtr pCert,
        [In]            UInt32 dwFlags,
        [In, Optional]  IntPtr pvReserved,
        [Out] out SafeNCryptKeyHandle phCryptProv,
        [Out] out UInt32 pdwKeySpec,
        [Out] out Boolean pfCallerFreeProv
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean PFXIsPFXBlob(
        [In] Wincrypt.CRYPTOAPI_BLOB Pfx
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean PFXVerifyPassword(
        [In] Wincrypt.CRYPTOAPI_BLOB Pfx,
        [MarshalAs(UnmanagedType.LPWStr)]
        [In] String szPassword,
        [In] UInt32 dwFlags
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern Boolean CryptFormatObject(
        [In]            UInt32 dwCertEncodingType,
        [In]            UInt32 dwFormatType,
        [In]            UInt32 dwFormatStrType,
        [In]            IntPtr pFormatStruct,
        [In]            String lpszStructType,
        [In]            Byte[] pbEncoded,
        [In]            UInt32 cbEncoded,
        [Out]           IntPtr pbFormat,
        [In, Out]ref UInt32 pcbFormat
    );
    #region Certificate property functions
    [DllImport(DLL_NAME, CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern UInt32 CertEnumCertificateContextProperties(
        [In] IntPtr pCertContext,
        [In] UInt32 dwPropId
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertGetCertificateContextProperty(
        [In]            IntPtr pCertContext,
        [In]            UInt32 dwPropId,
        [Out]           Byte[] pvData,
        [In, Out]ref UInt32 pcbData
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertGetCertificateContextProperty(
        [In]            IntPtr pCertContext,
        [In]            UInt32 dwPropId,
        [Out]           IntPtr pvData,
        [In, Out]ref UInt32 pcbData
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertGetCertificateContextProperty(
        [In]            IntPtr pCertContext,
        [In]            X509CertificatePropertyType dwPropId,
        [Out]           IntPtr pvData,
        [In, Out]ref UInt32 pcbData
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertGetCertificateContextProperty(
        [In]            IntPtr pCertContext,
        [In]            X509CertificatePropertyType dwPropId,
        [Out]           Byte[] pvData,
        [In, Out]ref UInt32 pcbData
    );
    [DllImport(DLL_NAME, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CertSetCertificateContextProperty(
        [In] IntPtr pCertContext,
        [In] X509CertificatePropertyType dwPropId,
        [In] UInt32 dwFlags,
        [In] IntPtr pvData
    );
    #endregion
}