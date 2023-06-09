namespace SysadminsLV.PKI.Dcom {
    enum AdcsBinaryFormat {
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
}