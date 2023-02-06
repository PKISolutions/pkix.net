using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Win32 {
    static class CryptUI {
        // http://msdn.microsoft.com/en-us/library/aa380290(VS.85).aspx
        [DllImport("Cryptui.dll", SetLastError = true)]
        public static extern Boolean CryptUIDlgViewContext(
            UInt32 dwContextType,
            SafeCTLHandleContext pvContext,
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPWStr)]
            String pwszTitle,
            UInt32 dwFlags,
            UInt32 pvReserved
        );
    }
}
