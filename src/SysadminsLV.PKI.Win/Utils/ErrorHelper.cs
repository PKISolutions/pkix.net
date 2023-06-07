using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Utils;
/// <summary>
/// Provides internal constants and static methods for Win32Error exceptions.
/// </summary>
public static class ErrorHelper {
    /// <summary>
    /// Converts Win32 error code to a corresponding text message
    /// </summary>
    /// <param name="errorCode">An error numeric value. A value can be passed as signed, unsigned integer or as a HEX string.</param>
    /// <remarks>When error code is passed as HEX, the string must be prepended with '0x' prefix.</remarks>
    /// <returns>Text representation of the error code.</returns>
    public static String GetMessage(Int32 errorCode) {
        UInt32 dwChars;

        const Int32 startBase = 12000;
        const Int32 endBase = 12176;
        String errorHex = $"{errorCode:x8}";
        Int32 lowBytes = Convert.ToInt32(errorHex.Substring(4, 4), 16);
        IntPtr lpMsgBuf = IntPtr.Zero;
        if (lowBytes > startBase & lowBytes < endBase) {
            IntPtr hModule = Kernel32.LoadLibrary("wininet.dll");
            dwChars = Kernel32.FormatMessage(0x1300, hModule, errorCode, 0, ref lpMsgBuf, 0, IntPtr.Zero);
            Kernel32.FreeLibrary(hModule);
        } else {
            dwChars = Kernel32.FormatMessage(0x1300, IntPtr.Zero, errorCode, 0, ref lpMsgBuf, 0, IntPtr.Zero);
        }
        if (dwChars != 0) {
            String message = $"Error: 0x{errorCode:x2}";
            String ptrToStringAnsi = Marshal.PtrToStringAnsi(lpMsgBuf);
            if (ptrToStringAnsi != null) {
                message = ptrToStringAnsi.Trim();
            }
            Kernel32.LocalFree(lpMsgBuf);
            return message;
        }
        return $"Unknown error: 0x{errorHex} (Win32: {errorCode})";
    }

    internal static Exception ComExceptionHandler(Exception e) {
        Regex regex = new Regex(@"\d{8}");
        Match match = regex.Match(e.Message);
        if (String.IsNullOrEmpty(match.Value)) { return e; }
        Int32 hresult = Convert.ToInt32(match.Value, 16);
        switch (match.Value) {
            case "80070005": return new UnauthorizedAccessException();
            case "80070057": return new ArgumentException();
            case "80094813": return new NotSupportedException(GetMessage(TemplateNotSupportedException));
            default: return new Win32Exception(hresult);
        }
    }

    internal const Int32 FileNotFoundException           = unchecked((Int32)0x80070002);
    internal const Int32 AccessDeniedException           = unchecked((Int32)0x80070005);
    internal const Int32 InavlidHandleException          = unchecked((Int32)0x80070006);
    internal const Int32 InvalidDataException            = unchecked((Int32)0x8007000d);
    internal const Int32 InvalidParameterException       = unchecked((Int32)0x80070057);
    internal const Int32 AlreadyInitializedException     = unchecked((Int32)0x800704df);
    internal const Int32 RpcUnavailableException         = unchecked((Int32)0x800706ba);
    internal const Int32 E_OBJECT_NOT_FOUND              = unchecked((Int32)0x800710D8);
    internal const Int32 E_INVALID_STATE                 = unchecked((Int32)0x8007139f);
    internal const Int32 InvalidCryptObjectException     = unchecked((Int32)0x80092009);
    internal const Int32 TemplateNotSupportedException   = unchecked((Int32)0x80094800);
    //internal const Int32 TemplateNotSupportedException = unchecked((Int32)0x80094813);

    internal const String E_DCUNAVAILABLE = "Unable to contact any domain controller.";
    internal const String E_STARTSTOPFAILED = "Failed to {0} certificate services on '{1}'.";
    internal const String InvalidCertCollection = "One or more certificates in the collection are not valid.";
    internal const String E_NONENTERPRISE = "Specified Certification Authority type is not supported. The CA type must be either 'Enterprise Root CA' or 'Enterprise Standalone CA'.";
    internal const String E_XCHGUNAVAILABLE = "Unable to retrieve any 'CA Exchange' certificates from '{0}'. This error may indicate that target CA server do not support key archival. All requests which require key archival will immediately fail.";
    internal const String E_TEMPLATENOTSUPPORTED = "The requested certificate template is not supported by this CA. Template name '{0}'.";
    internal const String E_COLLECTIONCLOSED = "The collection is in read-only mode.";
    internal const String E_AUDITNOTSUPPOERTED = "Audit control is not supported for this object.";
}
