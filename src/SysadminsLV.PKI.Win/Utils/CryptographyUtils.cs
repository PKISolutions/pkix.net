using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace PKI.Utils;

/// <summary>
/// Contains helper methods for cryptographic objects.
/// </summary>
public static class CryptographyUtils {
    
    /// <summary>
    /// Converts a default instance of <see cref="Pkcs9AttributeObject"/> class to a specific attribute implementation object. 
    /// </summary>
    /// <param name="attribute">Default instance of <see cref="Pkcs9AttributeObject"/> class.</param>
    /// <returns>Explicit attribute implementation if defined, otherwise, the same object is returned.</returns>
    public static Pkcs9AttributeObject ConvertAttribute(Pkcs9AttributeObject attribute) {
        // reserved for future use
        switch (attribute.Oid.Value) {
            default:
                return attribute;
        }
    }
    /// <summary>
    /// Tests whether the running operating system supports Cryptography Next Generation (CNG).
    /// </summary>
    /// <returns>
    /// <strong>True</strong> if running operating system supports Cryptography Next Generation (CNG),
    /// otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// Windows operating systems starting with Windows Vista/Windows Server 2008 always return <strong>True</strong>.
    /// </remarks>
    [Obsolete("This method is obsolete.", true)]
    public static Boolean TestCNGCompat() {
        return Environment.OSVersion.Version.Major >= 6;
    }
    /// <summary>
    /// Tests whether running operating system is compatible with OLE automation.
    /// </summary>
    /// <returns>
    /// <strong>True</strong> if running operating system is compatible with OLE automation,
    /// otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// Windows operating systems starting with Windows 8.1/Windows Server 2012 R2 return <strong>True</strong>.
    /// </remarks>
    [Obsolete("This method is obsolete.", true)]
    public static Boolean TestOleCompat() {
        if (Environment.OSVersion.Version.Major < 6) { return false; }
        return Environment.OSVersion.Version.Major != 6 || Environment.OSVersion.Version.Minor >= 3;
    }
    /// <summary>
    /// Tests whether running operating system is compatible with ADCS Web Services.
    /// </summary>
    /// <returns>
    /// <strong>True</strong> if running operating system supports ADCS Web Services, otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// Windows operating systems starting with Windows7/Windows Server 2008 R2 return <strong>True</strong>.
    /// </remarks>
    public static Boolean TestCepCompat() {
        if (Environment.OSVersion.Version.Major < 6) { return false; }
        return Environment.OSVersion.Version.Major != 6 || Environment.OSVersion.Version.Minor != 0;
    }
    /// <summary>
    /// Releases all references to a Runtime Callable Wrapper (RCW) by setting its reference count to 0.
    /// </summary>
    /// <param name="ComObject">The RCW to be released.</param>
    public static void ReleaseCom(params Object[] ComObject) {
        if (ComObject == null) { return; }
        foreach (Object rcw in ComObject.Where(x => x != null)) {
            Marshal.FinalReleaseComObject(rcw);
        }
    }
    /// <summary>
    /// Converts unicode DER string to ASN.1-encoded byte array.
    /// </summary>
    /// <param name="str">Unicode string.</param>
    /// <returns>ASN.1-encoded byte array.</returns>
    /// <remarks>This method is necessary for ADCS interoperability.</remarks>
    public static Byte[] DecodeDerString(String str) {
        if (String.IsNullOrEmpty(str)) {
            throw new ArgumentNullException(nameof(str));
        }
        return Encoding.Unicode.GetBytes(str);
    }
    /// <summary>
    /// Converts ASN.1-encoded byte array to unicode string.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <returns>Unicode string.</returns>
    /// <remarks>This method is necessary for ADCS interoperability.</remarks>
    public static String EncodeDerString(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        if (rawData.Length == 0) { throw new ArgumentException("The vlue is empty"); }
        List<Byte> rawBytes;
        if (rawData.Length % 2 > 0) {
            rawBytes = new List<Byte>(rawData.Length + 1);
            rawBytes.AddRange(rawData);
            rawBytes.Add(0);
        } else {
            rawBytes = new List<Byte>(rawData);
        }
        var sb = new StringBuilder(rawBytes.Count / 2);
        for (Int32 index = 0; index < rawBytes.Count; index += 2) {
            sb.Append(Convert.ToChar(rawBytes[index + 1] << 8 | rawBytes[index]));
        }
        return sb.ToString();
    }
}