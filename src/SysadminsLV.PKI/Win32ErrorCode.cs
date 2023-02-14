using System;

namespace SysadminsLV.PKI;
static class Win32ErrorCode {
    public const Int32 FileNotFoundException         = unchecked((Int32)0x80070002);
    public const Int32 AccessDeniedException         = unchecked((Int32)0x80070005);
    public const Int32 InvalidHandleException        = unchecked((Int32)0x80070006);
    public const Int32 InvalidDataException          = unchecked((Int32)0x8007000d);
    public const Int32 InvalidParameterException     = unchecked((Int32)0x80070057);
    public const Int32 AlreadyInitializedException   = unchecked((Int32)0x800704df);
    public const Int32 InvalidCryptObjectException   = unchecked((Int32)0x80092009);
    public const Int32 TemplateNotSupportedException = unchecked((Int32)0x80094800);
}
