using System;
using System.ComponentModel;
using System.IO;
using System.Text;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI;

public class CryptBinaryConverter {
    static String getRawText(String path) {
        using StreamReader sr = new StreamReader(path);
        return sr.ReadToEnd();
    }
    static String getRawText(String path, Encoding encoding) {
        if (Equals(encoding, Encoding.Default)) {
            encoding = Encoding.GetEncoding("iso-8859-1");
        }

        using var sr = new StreamReader(path, encoding);
        return sr.ReadToEnd();
    }

    /// <summary>
    /// Converts input string to a byte array. See <strong>Remarks</strong> for more details.
    /// </summary>
    /// <param name="anyString">
    /// 	A string encoded in Base64, hex or binary text.
    /// </param>
    /// <exception cref="Win32Exception">If the input string cannot be recognized and/or decoded.</exception>
    /// <exception cref="ArgumentNullException">Input string is null or empty.</exception>
    /// <returns>Decoded bytes</returns>
    /// <remarks>
    /// 	This method is used to decode cryptographic messages formatted in various ways, such Base64 with or
    /// 	without headers, hex string, with or without address and ASCII panels or pure binary text.
    /// 	<para>This method attempts to decode string in the following order:</para>
    /// 	<list type="bullet">
    /// 		<item>CRYPT_STRING_HEXADDR</item>
    /// 		<item>CRYPT_STRING_HEXASCIIADDR</item>
    /// 		<item>CRYPT_STRING_HEX</item>
    /// 		<item>CRYPT_STRING_HEXRAW</item>
    /// 		<item>CRYPT_STRING_HEXASCII</item>
    /// 		<item>CRYPT_STRING_BASE64HEADER</item>
    /// 		<item>CRYPT_STRING_BASE64</item>
    /// 		<item>CRYPT_STRING_BINARY</item>
    /// 	</list>
    /// </remarks>
    public static Byte[] AnyToBinary(String anyString) {
        if (String.IsNullOrEmpty(anyString)) { throw new ArgumentNullException(nameof(anyString)); }
        try {
            return AsnFormatter.StringToBinary(anyString, EncodingType.HexAny);
        } catch {
            try {
                return AsnFormatter.StringToBinary(anyString, EncodingType.Base64Any);
            } catch {
                return AsnFormatter.StringToBinary(anyString, EncodingType.Binary);
            }
        }
    }
    /// <summary>
    /// Reads the file which is either in binary or base64 encoding or hex formatted and returns decoded bytes.
    /// </summary>
    /// <param name="path">Specifies the path to a file to read.</param>
    /// <exception cref="ArgumentException">The file cannot be read.</exception>
    /// <exception cref="Win32Exception">The system cannot find the file specified.</exception>
    /// <returns>Decoded binary copy of the file.</returns>
    public static Byte[] CryptFileToBinary(String path) {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists) {
            throw new Win32Exception(2);
        }
        Byte[] buffer = new Byte[4];
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            fs.Read(buffer, 0, 4);
        }

        if (
            buffer[0] == 0xfe && buffer[1] == 0xff // big-endian unicode
            || buffer[0] == 0xff && buffer[1] == 0xfe // little-endian unicode
            || buffer[0] == 0xff && buffer[1] == 0xfe && buffer[2] == 0 && buffer[3] == 0 // UTF32
            || buffer[0] == 0xef && buffer[1] == 0xbb && buffer[2] == 0xbf // UTF8
            || buffer[0] == 0x2b && buffer[1] == 0x2f && buffer[2] == 0x76 // UTF7
        ) {
            return AnyToBinary(getRawText(path));
        }
        String inputString = getRawText(path, Encoding.Default);
        return inputString.Length == fileInfo.Length
            ? AnyToBinary(inputString)
            : File.ReadAllBytes(path);
    }
}