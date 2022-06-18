using System;
using System.Runtime.InteropServices;

namespace SysadminsLV.PKI.Structs {
    static class OleAut {
        // from [MS-OLEAUT]
        public const Int16 VT_NULL        = 0x0001;
        public const Int16 VT_I2          = 0x0002;
        public const Int16 VT_I4          = 0x0003;
        public const Int16 VT_R4          = 0x0004;
        public const Int16 VT_R8          = 0x0005;
        public const Int16 VT_CY          = 0x0006;
        public const Int16 VT_DATE        = 0x0007;
        public const Int16 VT_BSTR        = 0x0008;
        public const Int16 VT_DISPATCH    = 0x0009;
        public const Int16 VT_ERROR       = 0x000A;
        public const Int16 VT_BOOL        = 0x000B;
        public const Int16 VT_VARIANT     = 0x000C;
        public const Int16 VT_UNKNOWN     = 0x000D;
        public const Int16 VT_DECIMAL     = 0x000E;
        public const Int16 VT_I1          = 0x0010;
        public const Int16 VT_UI1         = 0x0011;
        public const Int16 VT_UI2         = 0x0012;
        public const Int16 VT_UI4         = 0x0013;
        public const Int16 VT_I8          = 0x0014;
        public const Int16 VT_UI8         = 0x0015;
        public const Int16 VT_INT         = 0x0016;
        public const Int16 VT_UINT        = 0x0017;
        public const Int16 VT_VOID        = 0x0018;
        public const Int16 VT_HRESULT     = 0x0019;
        public const Int16 VT_PTR         = 0x001A;
        public const Int16 VT_SAFEARRAY   = 0x001B;
        public const Int16 VT_CARRAY      = 0x001C;
        public const Int16 VT_USERDEFINED = 0x001D;
        public const Int16 VT_LPSTR       = 0x001E;
        public const Int16 VT_LPWSTR      = 0x001F;
        public const Int16 VT_RECORD      = 0x0024;
        public const Int16 VT_INT_PTR     = 0x0025;
        public const Int16 VT_UINT_PTR    = 0x0026;
        public const Int16 VT_ARRAY       = 0x2000;
        public const Int16 VT_BYREF       = 0x4000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct VARIANT {
            public Int16 vt;
            public Int16 wReserved1;
            public Int16 wReserved2;
            public Int16 wReserved3;
            public IntPtr pvRecord;
        }
    }
}
