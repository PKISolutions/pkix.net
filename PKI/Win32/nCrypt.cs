using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;
using SysadminsLV.PKI.Tools.MessageOperations;

namespace SysadminsLV.PKI.Win32 {
    static class NCrypt {
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptEnumStorageProviders(
            ref UInt32 pImplCount,
            ref IntPtr ppImplList,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptOpenStorageProvider(
            out SafeNCryptProviderHandle phProvider,
            [MarshalAs(UnmanagedType.LPWStr)]
            String pszProviderName,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptEnumAlgorithms(
            SafeNCryptProviderHandle hProvider,
            UInt32 dwAlgOperations,
            ref Int32 pdwAlgCount,
            ref IntPtr ppAlgList,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptFreeBuffer(
            [In]            IntPtr pvInput
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptFreeObject(
            [In]            IntPtr phProvider
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptEnumKeys(
            IntPtr hProvider,
            [MarshalAs(UnmanagedType.LPWStr)]
            String pszScope,
            ref IntPtr ppKeyName,
            ref IntPtr ppEnumState,
            UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptOpenKey(
            [In] SafeNCryptProviderHandle hProvider,
            [Out] out SafeNCryptKeyHandle phKey,
            [MarshalAs(UnmanagedType.LPWStr)] [In] String pszKeyName,
            [In] UInt32 dwLegacyKeySpec,
            [In] UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptImportKey(
            [In] SafeNCryptProviderHandle hProvider,
            [In, Optional] IntPtr hImportKey,
            [MarshalAs(UnmanagedType.LPWStr)]
            [In] String pszBlobType,
            [In, Optional] IntPtr pParameterList,
            [Out] out SafeNCryptKeyHandle phKey,
            [In] Byte[] pbData,
            [In] Int32 cbData,
            [In] NCryptImportFlags dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptExportKey(
            [In] SafeNCryptKeyHandle hKey,
            [In, Optional]    IntPtr hExportKey,
            [MarshalAs(UnmanagedType.LPWStr)]
            [In]              String pszBlobType,
            [In, Optional]    IntPtr pParameterList,
            [Out, Optional]   Byte[] pbOutput,
            [In]              Int32  cbOutput,
            [Out]             out Int32 pcbResult,
            [In]              UInt32 dwFlags
        );
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern Int32 NCryptFinalizeKey(SafeNCryptKeyHandle hKey, Int32 dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern Int32 NCryptDeleteKey(
            [In] SafeNCryptKeyHandle hKey,
            [In] UInt32 dwFlags
        );

        // for ECDSA
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptSignHash(
            [In] SafeNCryptKeyHandle hKey,
            [In, Optional]  IntPtr pPaddingInfo,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbSignature,
            [In] Int32 cbSignature,
            [Out] out Int32 pcbResult,
            [In] Int32 dwFlags
        );
        // for rsa-PKCS1 padding
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptSignHash(
            [In] SafeNCryptKeyHandle hKey,
            [In] ref nCrypt2.BCRYPT_PKCS1_PADDING_INFO pPaddingInfo,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [Out, MarshalAs(UnmanagedType.LPArray)] Byte[] pbSignature,
            [In] Int32 cbSignature,
            [Out] out Int32 pcbResult,
            [In] SignaturePadding dwFlags
        );
        // for rsa-PSS padding
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptSignHash(
            [In] SafeNCryptKeyHandle hKey,
            [In] ref nCrypt2.BCRYPT_PSS_PADDING_INFO pPaddingInfo,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [Out, MarshalAs(UnmanagedType.LPArray)] Byte[] pbSignature,
            [In] Int32 cbSignature,
            [Out] out Int32 pcbResult,
            [In] SignaturePadding dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptVerifySignature(
            [In] SafeNCryptKeyHandle hKey,
            [In, Optional] IntPtr pPaddingInfo,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [Out, MarshalAs(UnmanagedType.LPArray)] Byte[] pbSignature,
            [In] Int32 cbSignature,
            [In] SignaturePadding dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptVerifySignature(
            [In] SafeNCryptKeyHandle hKey,
            [In] ref nCrypt2.BCRYPT_PKCS1_PADDING_INFO pPaddingInfo,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [Out, MarshalAs(UnmanagedType.LPArray)]
            Byte[] pbSignature,
            [In] Int32 cbSignature,
            [In] SignaturePadding dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptVerifySignature(
            [In] SafeNCryptKeyHandle hKey,
            [In] ref nCrypt2.BCRYPT_PSS_PADDING_INFO pPaddingInfo,
            [In, MarshalAs(UnmanagedType.LPArray)] Byte[] pbHashValue,
            [In] Int32 cbHashValue,
            [Out, MarshalAs(UnmanagedType.LPArray)]
            Byte[] pbSignature,
            [In] Int32 cbSignature,
            [In] SignaturePadding dwFlags
        );
        [DllImport("ncrypt.dll", SetLastError = true)]
        public static extern Int32 NCryptTranslateHandle(
            [Out, Optional] IntPtr phProvider,
            [Out] out SafeNCryptKeyHandle phKey,
            [In] SafeHandle hLegacyProv,
            [In, Optional] IntPtr hLegacyKey,
            [In, Optional] UInt32 dwLegacyKeySpec,
            [In] Int32 dwFlags
        );
    }
}
