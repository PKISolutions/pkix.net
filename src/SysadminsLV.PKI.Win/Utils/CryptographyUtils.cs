using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace SysadminsLV.PKI.Utils;

/// <summary>
/// Contains helper methods for cryptographic objects.
/// </summary>
public static class CryptographyUtils {
    
    /// <summary>
    /// Converts a default instance of <see cref="Pkcs9AttributeObject"/> class to a specific attribute implementation object. 
    /// </summary>
    /// <param name="attribute">Default instance of <see cref="Pkcs9AttributeObject"/> class.</param>
    /// <returns>Explicit attribute implementation if defined, otherwise, the same object is returned.</returns>
    public static Pkcs9AttributeObject ConvertAttribute(this Pkcs9AttributeObject attribute) {
        // reserved for future use
        switch (attribute.Oid.Value) {
            default:
                return attribute;
        }
    }
    
    /// <summary>
    /// Releases all references to a Runtime Callable Wrapper (RCW) by setting its reference count to 0.
    /// </summary>
    /// <param name="comObject">The RCW to be released.</param>
    public static void ReleaseCom(params Object[] comObject) {
        if (comObject == null) { return; }
        foreach (Object rcw in comObject.Where(x => x != null)) {
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
        if (rawData.Length == 0) { throw new ArgumentException("The value is empty"); }
        List<Byte> rawBytes;
        if (rawData.Length % 2 > 0) {
            rawBytes = [..rawData, 0];
        } else {
            rawBytes = [..rawData];
        }
        var sb = new StringBuilder(rawBytes.Count / 2);
        for (Int32 index = 0; index < rawBytes.Count; index += 2) {
            sb.Append(Convert.ToChar(rawBytes[index + 1] << 8 | rawBytes[index]));
        }
        return sb.ToString();
    }
}