using System;
using System.Runtime.InteropServices;

namespace SysadminsLV.PKI.Win32;

/// <summary>
/// Contains only unmanaged function p/invoke definitions which are defined in <strong>AdvAPI.dll</strong> library.
/// </summary>
static class AdvAPI {
    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptAcquireContext(
        ref IntPtr phProv,
        String pszContainer,
        String pszProvider,
        UInt32 dwProvType,
        Int64 dwFlags
    );
    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptReleaseContext(
        IntPtr hProv,
        UInt32 dwFlags
    );
    /// <summary>
    /// No topic.
    /// </summary>
    /// <param name="hKey">No topic.</param>
    /// <returns>No topic.</returns>
    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern Boolean CryptDestroyKey(
        IntPtr hKey
    );
}