using System;
using System.Runtime.InteropServices;

namespace SysadminsLV.PKI.Win32 {
    static class Cryptnet {
        // http://msdn.microsoft.com/en-us/library/aa380080(VS.85).aspx
        [DllImport("Cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptGetObjectUrl(
            UInt32 pszUrlOid,
            IntPtr pvPara,
            UInt32 dwFlags,
            Byte[] pUrlArray,
            ref UInt32 pcbUrlArray,
            IntPtr pUrlInfo,
            ref UInt32 pcbUrlInfo,
            UInt32 pvReserved
        );
        // http://msdn.microsoft.com/en-us/library/aa380080(VS.85).aspx
        [DllImport("Cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptGetObjectUrl(
            [MarshalAs(UnmanagedType.LPStr)]
            String pszUrlOid,
            IntPtr pvPara,
            UInt32 dwFlags,
            Byte[] pUrlArray,
            ref UInt32 pcbUrlArray,
            IntPtr pUrlInfo,
            ref UInt32 pcbUrlInfo,
            UInt32 pvReserved
        );
    }
}
