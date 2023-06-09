using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using PKI.Structs;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Contains extension methods for <see cref="X509Certificate2"/> class.
/// </summary>
public static class X509Certificate2Extensions {
    /// <summary>
    /// Gets the list of certificate properties associated with the current certificate object.
    /// </summary>
    /// <param name="cert">Certificate.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>cert</strong> parameter is null reference.
    /// </exception>
    /// <exception cref="UninitializedObjectException">
    /// Certificate object is not initialized and is empty.
    /// </exception>
    /// <returns>An array of certificate context property types associated with the current certificate.</returns>
    public static X509CertificatePropertyType[] GetCertificateContextPropertyList(this X509Certificate2 cert) {
        if (cert == null) {
            throw new ArgumentNullException(nameof(cert));
        }
        if (IntPtr.Zero.Equals(cert.Handle)) {
            throw new UninitializedObjectException();
        }
        var props = new List<X509CertificatePropertyType>();
        UInt32 propID = 0;
        while ((propID = Crypt32.CertEnumCertificateContextProperties(cert.Handle, propID)) > 0) {
            props.Add((X509CertificatePropertyType)propID);
        }
        return props.ToArray();
    }
    /// <summary>
    /// Gets a specified certificate context property.
    /// </summary>
    /// <param name="cert">Certificate.</param>
    /// <param name="propID">Property ID to retrieve.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>cert</strong> parameter is null reference.
    /// </exception>
    /// <exception cref="UninitializedObjectException">
    /// Certificate object is not initialized and is empty.
    /// </exception>
    /// <exception cref="Exception">
    /// Requested context property is not found for the current certificate object.
    /// </exception>
    /// <returns>Specified certificate context property.</returns>
    public static X509CertificateContextProperty GetCertificateContextProperty(this X509Certificate2 cert, X509CertificatePropertyType propID) {
        if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
        if (IntPtr.Zero.Equals(cert.Handle)) { throw new UninitializedObjectException(); }
        UInt32 pcbData = 0;
        switch (propID) {
            case X509CertificatePropertyType.Handle:
            case X509CertificatePropertyType.KeyContext:
            case X509CertificatePropertyType.ProviderInfo:
                if (!Crypt32.CertGetCertificateContextProperty(cert.Handle, propID, IntPtr.Zero, ref pcbData)) {
                    throw new Exception("No such property.");
                }
                IntPtr ptr = Marshal.AllocHGlobal((Int32)pcbData);
                Crypt32.CertGetCertificateContextProperty(cert.Handle, propID, ptr, ref pcbData);
                try {
                    return new X509CertificateContextProperty(cert, propID, ptr);
                } finally {
                    Marshal.FreeHGlobal(ptr);
                }
            // byte[]
            default:
                if (!Crypt32.CertGetCertificateContextProperty(cert.Handle, propID, null, ref pcbData)) {
                    throw new Exception("No such property.");
                }
                Byte[] bytes = new Byte[pcbData];
                Crypt32.CertGetCertificateContextProperty(cert.Handle, propID, bytes, ref pcbData);
                return new X509CertificateContextProperty(cert, propID, bytes);
        }
    }
    /// <summary>
    /// Gets a collection of certificate context properties associated with the current certificate. If no
    /// property is associated, an empty collection will be returned.
    /// </summary>
    /// <param name="cert">Certificate.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>cert</strong> parameter is null reference.
    /// </exception>
    /// <exception cref="UninitializedObjectException">
    /// Certificate object is not initialized and is empty.
    /// </exception>
    /// <returns>A collection of certificate context properties.</returns>
    public static X509CertificateContextPropertyCollection GetCertificateContextProperties(this X509Certificate2 cert) {
        if (cert == null) { throw new ArgumentNullException(nameof(cert)); }
        if (IntPtr.Zero.Equals(cert.Handle)) { throw new UninitializedObjectException(); }
        X509CertificatePropertyType[] props = GetCertificateContextPropertyList(cert);
        X509CertificateContextPropertyCollection properties = new X509CertificateContextPropertyCollection();
        foreach (X509CertificatePropertyType propID in props) {
            properties.Add(GetCertificateContextProperty(cert, propID));
        }
        return properties;
    }
    /// <summary>
    /// Deletes private key material associated with a X.509 certificate from file system or hardware storage.
    /// </summary>
    /// <param name="cert">An instance of X.509 certificate.</param>
    /// <returns>
    /// <strong>True</strong> if associated private key was found and successfully deleted, otherwise <strong>False</strong>.
    /// </returns>
    public static Boolean DeletePrivateKey(this X509Certificate2 cert) {
        if (!Crypt32.CryptAcquireCertificatePrivateKey(
                cert.Handle,
                Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                IntPtr.Zero,
                out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
                out UInt32 pdwKeySpec,
                out Boolean _)) { return false; }
        return pdwKeySpec == UInt32.MaxValue
            ? deleteCngKey(phCryptProvOrNCryptKey)
            : deleteLegacyKey(cert.PrivateKey);
    }
    static Boolean deleteLegacyKey(AsymmetricAlgorithm privateKey) {
        if (privateKey == null) { return false; }
        String keyContainer;
        String provName;
        UInt32 provType;
        switch (privateKey) {
            case RSACryptoServiceProvider rsaProv:
                keyContainer = rsaProv.CspKeyContainerInfo.KeyContainerName;
                provName = rsaProv.CspKeyContainerInfo.ProviderName;
                provType = (UInt32) rsaProv.CspKeyContainerInfo.ProviderType;
                break;
            case DSACryptoServiceProvider dsaProv:
                keyContainer = dsaProv.CspKeyContainerInfo.KeyContainerName;
                provName = dsaProv.CspKeyContainerInfo.ProviderName;
                provType = (UInt32) dsaProv.CspKeyContainerInfo.ProviderType;
                break;
            default:
                privateKey.Dispose();
                return false;
        }
        IntPtr phProv = IntPtr.Zero;
        Boolean status2 = false;
        Boolean status1 = AdvAPI.CryptAcquireContext(
            ref phProv,
            keyContainer,
            provName,
            provType,
            Wincrypt.CRYPT_DELETEKEYSET | nCrypt2.NCRYPT_MACHINE_KEY_FLAG);
        if (!status1) {
            status2 = AdvAPI.CryptAcquireContext(
                ref phProv,
                keyContainer,
                provName,
                provType,
                Wincrypt.CRYPT_DELETEKEYSET);
        }
        privateKey.Dispose();
        return status1 || status2;
    }
    static Boolean deleteCngKey(SafeNCryptKeyHandle phKey) {
        Int32 hresult = NCrypt.NCryptDeleteKey(phKey, 0);
        phKey.Dispose();
        return hresult == 0;
    }
}