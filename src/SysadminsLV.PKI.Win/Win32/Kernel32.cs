using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace SysadminsLV.PKI.Win32;
/// <summary>
/// Contains only unmanaged function p/invoke definitions which are defined in <strong>Kernel32.dll</strong> library.
/// </summary>
public static class Kernel32 {
    const String DLL_NAME = "kernel32.dll";

    [DllImport(DLL_NAME, SetLastError = true)]
    public static extern UInt32 FormatMessage(
        UInt32 dwFlags,
        IntPtr lpSource,
        Int32 dwMessageId,
        UInt32 dwLanguageId,
        ref IntPtr lpBuffer,
        UInt32 nSize,
        IntPtr Arguments
    );
    [DllImport(DLL_NAME, SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(
        [In] String lpFileName
    );
    [DllImport(DLL_NAME, SetLastError = true, CharSet = CharSet.Auto)]
    public static extern Boolean FreeLibrary(
        [In] IntPtr hModule
    );
    [DllImport(DLL_NAME, SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibraryEx(
        [In] String lpFileName,
        [In] IntPtr hFile,
        [In] UInt32 dwFlags
    );
    [DllImport(DLL_NAME)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release method")]
    public static extern IntPtr LocalFree(
        IntPtr hMem
    );
}
