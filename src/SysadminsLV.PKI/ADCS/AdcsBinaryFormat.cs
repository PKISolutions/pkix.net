using System;

namespace SysadminsLV.PKI.ADCS;
// TODO: add xml-docs

public enum AdcsBinaryFormat {
    Base64CertHeader = 0x0,
    Base64NoHeader   = 0x1,
    Binary           = 0x3,
    Base64ReqHeader  = 0x4,
    Hex              = 0x5,
    Base64CrlHeader  = 0x9,
    HexAddr          = 0xA,
    HexAsciiAddr     = 0xB,
    HexRaw           = 0xC
}
public enum CertConfigOption {
    DefaultConfig           = 0,
    UIPickConfig            = 1,
    FirstConfig             = 2,
    LocalConfig             = 3,
    LocalActiveConfig       = 4,
    UIPickConfigSkipLocalCA = 5
}
[Flags]
public enum CertSrvPlatformVersion {
    Unknown     = 0,
    Win2000     = 0x00010001,
    Win2003     = 0x00020002,
    Win2008     = 0x00030001,
    Win2008R2   = 0x00040001,
    Win2012     = 0x00050001,
    Win2012R2   = 0x00060001,
    Win2016Plus = 0x00070001,
    AdvancedSku = unchecked((Int32)0x80000000)
}