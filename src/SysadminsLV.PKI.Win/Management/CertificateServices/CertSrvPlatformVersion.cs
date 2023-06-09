using System;

namespace SysadminsLV.PKI.Management.CertificateServices {
    [Flags]
    enum CertSrvPlatformVersion {
        Unknown     = 0,
        Win2000     = 0x00010001,
        Win2003     = 0x00020002,
        Win2008     = 0x00030001,
        Win2008R2   = 0x00040001,
        Win2012     = 0x00050001,
        Win2012R2   = 0x00060001,
        Win2016     = 0x00070001,
        AdvancedSku = unchecked((Int32)0x80000000)
    }
}