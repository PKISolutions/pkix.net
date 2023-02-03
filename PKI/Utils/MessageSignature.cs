using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using PKI.Exceptions;
using PKI.Structs;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Win32;

namespace PKI.Utils {
    #region OIDs
    //Value                     FriendlyName
    //-----                     ------------
    //1.2.840.113549.2.5        md5
    //1.2.840.113549.1.1.4      md5RSA
    //1.3.14.3.2.26             sha1
    //1.2.840.113549.1.1.5      sha1RSA
    //2.16.840.1.101.3.4.2.1    sha256
    //1.2.840.113549.1.1.11     sha256RSA
    //2.16.840.1.101.3.4.2.2    sha384
    //1.2.840.113549.1.1.12     sha384RSA
    //2.16.840.1.101.3.4.2.3    sha512
    //1.2.840.113549.1.1.13     sha512RSA
    #endregion
    /// <summary>
    /// Provides methods to work with digital signatures.
    /// </summary>
    /// <remarks>
    /// This class proides methods to work only with <strong>RSA</strong> signatures. To work with authenticode signatures use
    /// <strong>Set-AuthenticodeSignature</strong> and <strong>Get-AuthenticodeSignature</strong> PowerShell cmdlets.
    /// </remarks>
    [Obsolete("Use MessageSigner class instead.", true)]
    public static class MessageSignature {
        static ECDsaCng bindPublicKey(PublicKey pubKey) {
            List<Byte> header = new List<Byte>();
            // headers from bcrypt.h
            switch (Asn1Utils.DecodeObjectIdentifier(pubKey.EncodedParameters.RawData).Value) {
                // ECDH_P256/ECDSA_P256
                case "1.2.840.10045.3.1.7":
                    header.AddRange(new Byte[] { 69, 67, 83, 49, 32, 0, 0, 0 });
                    break;
                // ECDH_P384/ECDSA_P384
                case "1.3.132.0.34":
                    header.AddRange(new Byte[] { 69, 67, 83, 51, 48, 0, 0, 0 });
                    break;
                // ECDH_P521/ECDSA_P521
                case "1.3.132.0.35":
                    header.AddRange(new Byte[] { 69, 67, 83, 53, 66, 0, 0, 0 });
                    break;
                default:
                    throw new CryptographicException("Specified ellyptic curve is not supported.");
            }
            // skip first byte, it is always 0X04 for ECDSA public key
            header.AddRange(pubKey.EncodedKeyValue.RawData.Skip(1));
            CngKey cngKey = CngKey.Import(header.ToArray(), CngKeyBlobFormat.GenericPublicBlob);
            return new ECDsaCng(cngKey);
        }
        static Boolean verifyRSA(PublicKey publicKey, Byte[] message, Byte[] signature, Oid hashalgorithm) {
            String halgName = hashalgorithm.FriendlyName.ToLower().Replace("rsa", null);
            Oid oid = new Oid(halgName);
            RSACryptoServiceProvider key = (RSACryptoServiceProvider)publicKey.Key;
            return key.VerifyData(message, oid.Value, signature);
        }
        static Boolean verifyDSA(PublicKey publicKey, Byte[] message, Byte[] signature) {
            DSACryptoServiceProvider key = (DSACryptoServiceProvider)publicKey.Key;
            return key.VerifyData(message, signature);
        }
        static Boolean verifyECC(ECDsaCng key, Byte[] message, Byte[] signature, String hashAlgorithm) {
            switch (hashAlgorithm) {
                case "1.2.840.113549.2.5":
                    key.HashAlgorithm = CngAlgorithm.MD5;
                    break;
                case "1.3.14.3.2.26":
                    key.HashAlgorithm = CngAlgorithm.Sha1;
                    break;
                case "2.16.840.1.101.3.4.2.1":
                    key.HashAlgorithm = CngAlgorithm.Sha256;
                    break;
                case "2.16.840.1.101.3.4.2.2":
                    key.HashAlgorithm = CngAlgorithm.Sha384;
                    break;
                case "2.16.840.1.101.3.4.2.3":
                    key.HashAlgorithm = CngAlgorithm.Sha512;
                    break;
            }
            return key.VerifyData(message, signature);
        }
        static Boolean verifySignature(PublicKey publicKey, Byte[] message, Byte[] signature, Oid hashalgorithm) {
            Oid2 oid = new Oid2(hashalgorithm.Value, OidGroup.SignatureAlgorithm, true);
            if (String.IsNullOrEmpty(oid.FriendlyName)) {
                throw new ArgumentException("Specified signature algorithm is not supported.");
            }
            switch (publicKey.Oid.Value) {
                // RSA
                case "1.2.840.113549.1.1.1":
                    return verifyRSA(publicKey, message, signature, hashalgorithm);
                // DSA
                case "1.2.840.10040.4.1":
                    return verifyDSA(publicKey, message, signature);
                // ECC
                case "1.2.840.10045.2.1":
                    ECDsaCng key = bindPublicKey(publicKey);
                    return verifyECC(key, message, signature, hashalgorithm.Value);
                default:
                    return false;
            }
        }
        static Byte[] calculateHash(Byte[] message, String hashalg, Boolean skip) {
            HashAlgorithm hasher = HashAlgorithm.Create(hashalg);
            if (hasher == null) {
                throw new ArgumentException("Invalid hashing algorithm is specified");
            }
            using (hasher) {
                if (!skip) {
                    Debug.Assert(hasher != null, "hasher != null");
                    return hasher.ComputeHash(message);
                }
            }
            return null;
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the signature using the provided public
        /// key and comparing it to the hash value of the provided data.
        /// </summary>
        /// <param name="certificate">An <see cref="X509Certificate2"/> object that represents signer certificate.</param>
        /// <param name="message">Signed message (without signature).</param>
        /// <param name="signature">Digital signature (encrypted hash) to verify.</param>
        /// <param name="hashalgorithm">Hash algorithm that was used to hash the data.</param>
        /// <returns><strong>True</strong> if the signature is valid. Otherwise <strong>False</strong>.</returns>
        public static Boolean VerifySignature(
            X509Certificate2 certificate,
            Byte[] message,
            Byte[] signature,
            Oid hashalgorithm
        ) {
            if (!IntPtr.Zero.Equals(certificate.Handle)) {
                PublicKey key = certificate.PublicKey;
                //hashalgorithm = new Oid(hashalgorithm.FriendlyName.ToLower().Replace("rsa", null).Replace("ecdsa", null));
                return verifySignature(key, message, signature, hashalgorithm);
            }
            throw new UninitializedObjectException();
        }
        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="certificate">An <see cref="X509Certificate2"/> object of the signer certificate.</param>
        /// <param name="message">Message to be signed.</param>
        /// <param name="hashAlgorithm">The name of the hash algorithm to use in the signature. For example, 'SHA256'</param>
        /// <returns>The signature for the specified data.</returns>
        public static Byte[] SignMessage(X509Certificate2 certificate, Byte[] message, Oid hashAlgorithm) {
            SafeNCryptKeyHandle phCryptProv = new SafeNCryptKeyHandle();
            UInt32 pdwKeySpec = 0;
            Boolean pfCallerFreeProv = false;
            if (!Crypt32.CryptAcquireCertificatePrivateKey(certificate.Handle, Wincrypt.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, IntPtr.Zero, out phCryptProv, out pdwKeySpec, out pfCallerFreeProv)) {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            // true -> CNG, false -> legacy
            if (pdwKeySpec == UInt32.MaxValue) {
                Byte[] hashBytes = calculateHash(message, hashAlgorithm.FriendlyName, false);
                try {
                    Int32 hresult = NCrypt.NCryptSignHash(phCryptProv, IntPtr.Zero, hashBytes, hashBytes.Length, null, 0, out Int32 pcbResult, 0);
                    if (hresult != 0) {
                        throw new CryptographicException(hresult);
                    }
                    Byte[] pbSignature = new Byte[pcbResult];
                    hresult = NCrypt.NCryptSignHash(phCryptProv, IntPtr.Zero, hashBytes, hashBytes.Length, pbSignature, pbSignature.Length, out pcbResult, 0);
                    if (hresult != 0) {
                        throw new CryptographicException(hresult);
                    }
                    return pbSignature;
                } finally {
                    if (pfCallerFreeProv) { NCrypt.NCryptFreeObject(phCryptProv.DangerousGetHandle()); }
                }
            }
            if (pfCallerFreeProv) { AdvAPI.CryptReleaseContext(phCryptProv.DangerousGetHandle(), 0); }
            calculateHash(message, hashAlgorithm.FriendlyName, false);
            RSACryptoServiceProvider key = (RSACryptoServiceProvider)certificate.PrivateKey;
            return key.SignData(message, hashAlgorithm.Value);
        }
    }
}
