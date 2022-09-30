using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;
using PKI.Exceptions;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Cryptography;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Utils.CLRExtensions {
    /// <summary>
    /// Contains extension methods for <see cref="X509Certificate2"/> class.
    /// </summary>
    public static class X509Certificate2Extensions {
        /// <summary>
        /// Converts generic X.509 extension objects to specialized certificate extension objects
        /// inherited from <see cref="X509Extension"/> class that provide extension-specific information.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>cert</strong> parameter is null reference.
        /// </exception>
        /// <returns>A collection of certificate extensions</returns>
        /// <remarks>
        /// This method can transform the following X.509 certificate extensions:
        /// <list type="bullet">
        /// <item><description><see cref="X509CertificateTemplateExtension"/></description></item>
        /// <item><description><see cref="X509ApplicationPoliciesExtension"/></description></item>
        /// <item><description><see cref="X509ApplicationPolicyMappingsExtension"/></description></item>
        /// <item><description><see cref="X509ApplicationPolicyConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509AuthorityInformationAccessExtension"/></description></item>
        /// <item><description><see cref="X509NonceExtension"/></description></item>
        /// <item><description><see cref="X509CRLReferenceExtension"/></description></item>
        /// <item><description><see cref="X509ArchiveCutoffExtension"/></description></item>
        /// <item><description><see cref="X509ServiceLocatorExtension"/></description></item>
        /// <item><description><see cref="X509SubjectKeyIdentifierExtension"/></description></item>
        /// <item><description><see cref="X509KeyUsageExtension"/></description></item>
        /// <item><description><see cref="X509SubjectAlternativeNamesExtension"/></description></item>
        /// <item><description><see cref="X509IssuerAlternativeNamesExtension"/></description></item>
        /// <item><description><see cref="X509BasicConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509CRLNumberExtension"/></description></item>
        /// <item><description><see cref="X509NameConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509CRLDistributionPointsExtension"/></description></item>
        /// <item><description><see cref="X509CertificatePoliciesExtension"/></description></item>
        /// <item><description><see cref="X509CertificatePolicyMappingsExtension"/></description></item>
        /// <item><description><see cref="X509AuthorityKeyIdentifierExtension"/></description></item>
        /// <item><description><see cref="X509CertificatePolicyConstraintsExtension"/></description></item>
        /// <item><description><see cref="X509EnhancedKeyUsageExtension"/></description></item>
        /// <item><description><see cref="X509FreshestCRLExtension"/></description></item>
        /// </list>
        /// Non-supported extensions will be returned as an <see cref="X509Extension"/> object.
        /// </remarks>
        public static X509ExtensionCollection ResolveExtensions (this X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(nameof(cert));
            }
            if (cert.Extensions.Count == 0) {
                return cert.Extensions;
            }
            var extensions = new X509ExtensionCollection();
            foreach (X509Extension ext in cert.Extensions) {
                extensions.Add(ext.ConvertExtension());
            }
            return extensions;
        }

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
            properties.Close();
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
            var hresult = NCrypt.NCryptDeleteKey(phKey, 0);
            phKey.Dispose();
            return hresult == 0;
        }

        /// <summary>
        /// Displays an X.509 certificate dump.
        /// </summary>
        /// <returns>Formatted string.</returns>
        public static String Format(this X509Certificate2 cert) {
            if (cert == null) {
                return String.Empty;
            }

            var blob = new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
            String sigValue = AsnFormatter.BinaryToString(blob.Signature.Value.Reverse().ToArray(), EncodingType.HexAddress)
                .Replace(Environment.NewLine, Environment.NewLine + "    ");
            var sb = new StringBuilder();


            sb.Append($@"X509 Certificate:
Version: {cert.Version} (0x{cert.Version - 1:x})
Serial Number: {cert.SerialNumber}

{blob.SignatureAlgorithm}
Issuer:
    {cert.IssuerName.FormatReverse(true).Replace(Environment.NewLine, Environment.NewLine + "    ")}
  Name Hash(md5)    : {getNameHash(cert.IssuerName, MD5.Create())}
  Name Hash(sha1)   : {getNameHash(cert.IssuerName, SHA1.Create())}
  Name Hash(sha256) : {getNameHash(cert.IssuerName, SHA256.Create())}

Valid From: {cert.NotBefore}
Valid To  : {cert.NotAfter}

Subject:
    {cert.SubjectName.FormatReverse(true).Replace(Environment.NewLine, Environment.NewLine + "    ")}
  Name Hash(md5)    : {getNameHash(cert.SubjectName, MD5.Create())}
  Name Hash(sha1)   : {getNameHash(cert.SubjectName, SHA1.Create())}
  Name Hash(sha256) : {getNameHash(cert.SubjectName, SHA256.Create())}

{cert.PublicKey.Format().TrimEnd()}

Certificate Extensions: {cert.Extensions.Count}
{cert.Extensions.Format()}

{blob.SignatureAlgorithm.ToString().TrimEnd()}
Signature: UnusedBits={blob.Signature.UnusedBits}
    {sigValue}
");
            sb.AppendLine(cert.Issuer.Equals(cert.Subject, StringComparison.InvariantCultureIgnoreCase)
                ? "Root Certificate: Subject matches Issuer"
                : "Non-root Certificate");
            sb.AppendLine($"Key Id Hash(sha1)       : {getHashData(cert.PublicKey.Encode(), SHA1.Create())}");
            sb.AppendLine($"Key Id Hash(rfc-md5)    : {getHashData(cert.PublicKey.EncodedKeyValue.RawData, MD5.Create())}");
            sb.AppendLine($"Key Id Hash(rfc-sha1)   : {getHashData(cert.PublicKey.EncodedKeyValue.RawData, SHA1.Create())}");
            sb.AppendLine($"Key Id Hash(rfc-sha256) : {getHashData(cert.PublicKey.EncodedKeyValue.RawData, SHA256.Create())}");
            sb.AppendLine($"Key Id Hash(pin-sha256-b64) : {getKeyPinHash(cert.PublicKey, SHA256.Create())}");
            sb.AppendLine($"Key Id Hash(pin-sha256-hex) : {getHashData(cert.PublicKey.Encode(), SHA256.Create())}");
            sb.AppendLine($"Cert Hash(md5)    : {getCertHash(cert, MD5.Create())}");
            sb.AppendLine($"Cert Hash(sha1)   : {getCertHash(cert, SHA1.Create())}");
            sb.AppendLine($"Cert Hash(sha256) : {getCertHash(cert, SHA256.Create())}");
            sb.AppendLine($"Signature Hash    : {getHashData(blob.GetRawSignature(), SHA1.Create())}");
            return sb.ToString();
        }
        static String getCertHash(X509Certificate2 cert, HashAlgorithm hasher) {
            return getHashData(cert.RawData, hasher);
        }
        static String getNameHash(AsnEncodedData name, HashAlgorithm hasher) {
            return getHashData(name.RawData, hasher);
        }
        static String getHashData(Byte[] rawData, HashAlgorithm hasher) {
            StringBuilder sb = new StringBuilder();
            using (hasher) {
                foreach (Byte b in hasher.ComputeHash(rawData)) {
                    sb.Append($"{b:x2}");
                }
            }

            return sb.ToString();
        }
        static String getKeyPinHash(PublicKey key, HashAlgorithm hasher) {
            using (hasher) {
                return Convert.ToBase64String(hasher.ComputeHash(key.Encode()));
            }
        }
    }
}
