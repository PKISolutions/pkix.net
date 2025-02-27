﻿using System;
using System.IO;
using PKI.Structs;
using SysadminsLV.PKI.Cryptography.Pkcs;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Utils.CLRExtensions;

/// <summary>
/// Contains extension methods for <see cref="FileInfo"/> class.
/// </summary>
public static class FileInfoExtensions {
    /// <summary>
    /// Gets PKCS#7 signature object of signed file. If file is not signed using authenticode signature, the method return null.
    /// </summary>
    /// <param name="fileInfo">An instance of file object.</param>
    /// <returns>Detached signature object.</returns>
    public static DefaultSignedPkcs7 GetSignatureObject(this FileInfo fileInfo) {
        if (!fileInfo.Exists) {
            return null;
        }
        const Int32 CMSG_ENCODED_MESSAGE = 29;

        if (!Crypt32.CryptQueryObject(
                Wincrypt.CERT_QUERY_OBJECT_FILE,
                fileInfo.FullName,
                Wincrypt.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                Wincrypt.CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                out Int32 _,
                out Int32 pdwContentType,
                out Int32 _,
                out IntPtr phCertStore,
                out IntPtr phMsg,
                out IntPtr ppvContext
            )) { return null; }

        if (!Crypt32.CryptMsgGetParam(phMsg, CMSG_ENCODED_MESSAGE, 0, null, out Int32 pcbData)) {
            return null;
        }

        Byte[] pvData = new Byte[pcbData];
        Crypt32.CryptMsgGetParam(phMsg, CMSG_ENCODED_MESSAGE, 0, pvData, out pcbData);
        Crypt32.CryptMsgClose(phMsg);
        Crypt32.CertCloseStore(phCertStore, 0);

        return new DefaultSignedPkcs7(pvData);
    }
}