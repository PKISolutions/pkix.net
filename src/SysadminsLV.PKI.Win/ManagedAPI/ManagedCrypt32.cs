using System;
using PKI.Structs;
using SysadminsLV.PKI.Win32;

namespace PKI.ManagedAPI;

/// <summary>
/// Contains safe implementations of unmanaged functions.
/// </summary>
public static class Crypt32Managed {
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
            using Wincrypt.CRYPTOAPI_BLOB PPfx = Wincrypt.CRYPTOAPI_BLOB.FromBinaryData(rawData);
            Boolean result = Crypt32.PFXIsPFXBlob(PPfx);
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
            using Wincrypt.CRYPTOAPI_BLOB PPfx = Wincrypt.CRYPTOAPI_BLOB.FromBinaryData(rawData);
            return Crypt32.PFXVerifyPassword(PPfx, password, 0);
        }
        throw new ArgumentNullException(nameof(rawData));
    }
    #endregion
}