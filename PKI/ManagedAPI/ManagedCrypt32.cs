using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Exceptions;
using PKI.Structs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Utils.CLRExtensions;
using SysadminsLV.PKI.Win32;

namespace PKI.ManagedAPI;

/// <summary>
/// Contains safe implementations of unmanaged functions.
/// </summary>
public static class Crypt32Managed {
    #region converters
    
    /// <summary>
    /// Converts a formatted string into an array of bytes.
    /// </summary>
    /// <param name="inputString">A string that contains the formatted string to be converted</param>
    /// <param name="inputEncoding">Indicates the format of the string to be converted. By default <strong>CRYPT_STRING_ANY
    ///	</strong> is used.</param>
    /// <returns>Pure binary array of the decoded string.</returns>
    [Obsolete("Use AsnFormatter.StringToBinary instead", true)]
    public static Byte[] CryptStringToBinary(String inputString, CryptEncoding inputEncoding = CryptEncoding.CRYPT_STRING_ANY) {
        UInt32 pcbBinary = 0;
        if (Crypt32.CryptStringToBinary(inputString, (UInt32)inputString.Length, (UInt32)inputEncoding, null, ref pcbBinary, 0, 0)) {
            Byte[] pbBinary = new Byte[pcbBinary];
            Crypt32.CryptStringToBinary(inputString, (UInt32)inputString.Length, (UInt32)inputEncoding, pbBinary, ref pcbBinary, 0, 0);
            return pbBinary;
        }
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    /// <summary>
    /// Converts an array of bytes into a formatted string.
    /// </summary>
    /// <param name="inputArray">A byte array to convert.</param>
    /// <param name="outputEncoding">Specifies the encoding of the resulting formatted string.</param>
    /// <param name="outputFormatting">pecifies the format of the resulting formatted string.</param>
    /// <exception cref="ArgumentException">The <strong>outputEncoding</strong> paramter contains invalid encoding flag.</exception>
    /// <returns>Encoded and formatted string.</returns>
    [Obsolete("Use AsnFormatter.BinaryToString instead", true)]
    public static String CryptBinaryToString(Byte[] inputArray, CryptEncoding outputEncoding, CryptFormatting outputFormatting) {
        if (
            outputEncoding == CryptEncoding.CRYPT_STRING_BASE64_ANY ||
            outputEncoding == CryptEncoding.CRYPT_STRING_ANY ||
            outputEncoding == CryptEncoding.CRYPT_STRING_HEX_ANY
        ) { throw new ArgumentException("Invalid encoding is specified."); }
        UInt32 flags = (UInt32)outputEncoding | (UInt32)outputFormatting;
        UInt32 pcchString = 0;
        if (Crypt32.CryptBinaryToString(inputArray, (UInt32)inputArray.Length, flags, null, ref pcchString)) {
            StringBuilder SB = new StringBuilder((Int32)pcchString);
            Crypt32.CryptBinaryToString(inputArray, (UInt32)inputArray.Length, flags, SB, ref pcchString);
            return SB.ToString();
        }
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    #endregion

    #region PFX tools
    /// <summary>
    /// Attempts to decode the outer layer of a BLOB as a PFX packet
    /// </summary>
    /// <param name="rawData">A byte array that the method will attempt to decode as a PFX packet</param>
    /// <exception cref="ArgumentNullException">If the <strong>rawData</strong> parameter is null.</exception>
    /// <returns>The function returns <strong>TRUE</strong> if the BLOB can be decoded as a PFX packet. If the outer
    ///  layer of the BLOB cannot be decoded as a PFX packet, the method returns <strong>FALSE.</strong></returns>
    public static Boolean PfxisPfxBlob(Byte[] rawData) {
        if (rawData != null) {
            IntPtr ptr = Marshal.AllocHGlobal(rawData.Length);
            Marshal.Copy(rawData, 0, ptr, rawData.Length);
            Wincrypt.CRYPTOAPI_BLOB PPfx = new Wincrypt.CRYPTOAPI_BLOB {
                                                                           cbData = (UInt32)rawData.Length,
                                                                           pbData = ptr
                                                                       };
            Boolean result = Crypt32.PFXIsPFXBlob(PPfx);
            Marshal.FreeHGlobal(ptr);
            return result;
        }
        throw new ArgumentNullException(nameof(rawData));
    }
    /// <summary>
    /// attempts to decode the outer layer of a BLOB as a Personal Information Exchange (PFX) packet and to decrypt it
    /// with the given password.
    /// </summary>
    /// <param name="rawData">A byte array that the method will attempt to decode as a PFX packet</param>
    /// <param name="password">String password to be checked. For this function to succeed, this password must be exactly the same 
    /// as the password used to encrypt the packet.
    /// <para>If you set this value to an empty string or <strong>NULL</strong>, this function typically attempts to decrypt the
    /// password embedded in the PFX BLOB by using the empty string or <strong>NULL</strong>.</para>
    /// <para>However, beginning with Windows 8 and Windows Server 2012, if a <strong>NULL</strong> or empty password was specified
    /// when the PFX BLOB was created and the application also specified that the password should be protected to an Active
    /// Directory (AD) principal, the Cryptography API (CAPI) randomly generates a password, encrypts it to the AD principal
    /// and embeds it in the PFX BLOB. The PFXVerifyPassword function will then try to use the specified AD principal (current
    ///  user, computer, or AD group member) to decrypt the password.</para>
    /// </param>
    /// <exception cref="ArgumentNullException">If the <strong>rawData</strong> parameter is null.</exception>
    /// <returns>The method return <strong>TRUE</strong> if the password appears correct; otherwise,
    /// it returns <strong>FALSE</strong>.
    /// </returns>
    public static Boolean PfxVerifyPassword(Byte[] rawData, String password) {
        if (rawData != null) {
            IntPtr ptr = Marshal.AllocHGlobal(rawData.Length);
            Marshal.Copy(rawData, 0, ptr, rawData.Length);
            Wincrypt.CRYPTOAPI_BLOB PPfx = new Wincrypt.CRYPTOAPI_BLOB {
                                                                           cbData = (UInt32)rawData.Length,
                                                                           pbData = ptr
                                                                       };
            Boolean result = Crypt32.PFXVerifyPassword(PPfx, password, 0);
            Marshal.FreeHGlobal(ptr);
            return result;
        }
        throw new ArgumentNullException(nameof(rawData));
    }
    #endregion

    /// <summary>
    /// Decodes an ASN.1-encoded byte array that represents complete X509Extension object to an instance of
    /// <see cref="X509Extension"/> instance.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array that represents requested object.</param>
    /// <returns>Decoded <see cref="X509Extension"/> object.</returns>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
    /// <exception cref="Asn1InvalidTagException">Byte array do not represent requested object.</exception>
    [Obsolete("Use X509ExtensionExtensions.Decode static method instead.", true)]
    public static X509Extension DecodeX509Extension(Byte[] rawData) {
        if (rawData == null) { throw new ArgumentNullException(nameof(rawData)); }
        Asn1Reader asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) { throw new Asn1InvalidTagException(asn.Offset); }
        asn.MoveNext();
        if (asn.Tag != (Byte) Asn1Type.OBJECT_IDENTIFIER) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        Oid oid = new Asn1ObjectIdentifier(asn).Value;
        Boolean critical = false;
        asn.MoveNext();
        if (asn.Tag == (Byte)Asn1Type.BOOLEAN) {
            critical = Asn1Utils.DecodeBoolean(asn.GetTagRawData());
            asn.MoveNext();
        }
        if (asn.Tag != (Byte) Asn1Type.OCTET_STRING) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        return new X509Extension(oid, asn.GetPayload(), critical).ConvertExtension();
    }
    /// <summary>
    /// 
    /// </summary>
    /// <param name="extension"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="UninitializedObjectException"></exception>
    [Obsolete("Use X509Extension.Encode extension method instead.", true)]
    public static Byte[] EncodeX509Extension(X509Extension extension) {
        if (extension == null) { throw new ArgumentNullException(nameof(extension)); }
        if (String.IsNullOrEmpty(extension.Oid.Value)) { throw new UninitializedObjectException(); }
        List<Byte> rawData = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(extension.Oid));
        if (extension.Critical) {
            rawData.AddRange(Asn1Utils.EncodeBoolean(true));
        }
        rawData.AddRange(Asn1Utils.Encode(extension.RawData, (Byte)Asn1Type.OCTET_STRING));
        return Asn1Utils.Encode(rawData.ToArray(), 48);
    }
    /// <summary>
    /// 
    /// </summary>
    /// <param name="rawData"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidDataException"></exception>
    [Obsolete("Use X509ExtensionCollection.Decode extension method.", true)]
    public static X509ExtensionCollection DecodeX509Extensions(Byte[] rawData) {
        var extensions = new X509ExtensionCollection();
        extensions.Decode(rawData);
        return extensions;
    }
    /// <summary>
    /// 
    /// </summary>
    /// <param name="extensions"></param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <returns></returns>
    [Obsolete("Use X509ExtensionCollection.Encode extension method.", true)]
    public static Byte[] EncodeX509Extensions(X509ExtensionCollection extensions) {
        return extensions.Encode();
    }
}