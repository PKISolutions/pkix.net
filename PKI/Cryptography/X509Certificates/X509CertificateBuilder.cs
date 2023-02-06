using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PKI.Structs;
using PKI.Utils;
using SysadminsLV.Asn1Parser;
using SysadminsLV.PKI.Tools.MessageOperations;
using SysadminsLV.PKI.Utils.CLRExtensions;
using SysadminsLV.PKI.Win32;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a version 3 X.509 certificate generator class. This class is intended to generate in-memory
/// certificates without having to install them in certificate store.
/// </summary>
/// <remarks>
/// Although, the certificate is created in-memory, private key material still persists in CSP/KSP. When the
/// certificate is no longer necessary, call <see cref="X509Certificate2Extensions.DeletePrivateKey">
/// X509Certificate2.DeletePrivateKey</see> extension method.
/// </remarks>
public class X509CertificateBuilder {
    readonly Byte[] _versionBytes = { 0xa0, 03, 02, 01, 02 };
    readonly HashSet<String> _excludedExtensions = new(
        new[] {
                  X509ExtensionOid.SubjectKeyIdentifier,
                  X509ExtensionOid.AuthorityKeyIdentifier
              }
    );
    readonly List<X509Extension> _extensions = new();
    X509ExtensionCollection finalExtensions;
    Byte[] serialNumber;

    /// <summary>
    /// Gets the version of X.509 certificate. This class creates only version 3 certificates.
    /// </summary>
    public Int32 Version => 3;
    /// <summary>
    /// Gets or sets a serial number. Input string must consist of hex characters only.
    /// </summary>
    public String SerialNumber { get; set; }
    /// <summary>
    /// Gets or sets subject of the certificate. If this is self-signed certificate, subject will be copied to
    /// issuer field.
    /// </summary>
    public X500DistinguishedName SubjectName { get; set; }
    /// <summary>
    /// Gets or sets the date in local time on which a certificate becomes valid. Default value is current
    /// date and time. If external signer is used, this value cannot be less than NotBefore value of the
    /// signer certificate.
    /// </summary>
    public DateTime NotBefore { get; set; } = DateTime.Now;
    /// <summary>
    /// Gets or sets the date in local time after which a certificate is no longer valid. This value cannot be
    /// earlier than <see cref="NotBefore"/> value. If external signer is used, this value cannot exceed NotAfter
    /// value of the signer certificate.
    /// </summary>
    public DateTime NotAfter { get; set; } = DateTime.Now.AddYears(1);
    /// <summary>
    /// Gets a collection of user-supplied extensions to include in certificate.
    /// </summary>
    /// <remarks>
    /// When adding extensions, <strong>Subject Key Identifier</strong> and <strong>Authority Key Identifier</strong>
    /// are generated at runtime and are ignored in this collection
    /// </remarks>
    public X509ExtensionCollection Extensions { get; } = new();
    /// <summary>
    /// Gets or sets hashing algorithm used to sign the certificate. Default value is SHA256.
    /// </summary>
    public Oid2 HashingAlgorithm { get; set; } = new(AlgorithmOid.SHA256, false);
    /// <summary>
    /// Gets or sets a value that indicates whether PKCS#1 v2.1 is used.
    /// </summary>
    public Boolean AlternateSignatureFormat { get; set; }
    /// <summary>
    /// Gets or sets a friend name for certificate.
    /// </summary>
    public String FriendlyName { get; set; }
    /// <summary>
    /// Gets an asymmetric key pair generator. Use this property to configure asymmetric key generation options.
    /// </summary>
    public X509PrivateKeyBuilder PrivateKeyInfo { get; } = new();

    void generateSerialNumber() {
        if (String.IsNullOrWhiteSpace(SerialNumber)) {
            using MD5 hasher = MD5.Create();
            serialNumber = hasher.ComputeHash(Guid.NewGuid().ToByteArray());
        } else {
            serialNumber = AsnFormatter.StringToBinary(SerialNumber, EncodingType.Hex);
        }
    }
    void validateDates(X509Certificate2 signer) {
        if (signer == null) {
            if (NotAfter <= NotBefore) {
                NotAfter = NotBefore.AddYears(1);
            }
        } else {
            if (NotBefore < signer.NotBefore) {
                NotBefore = signer.NotBefore;
            }

            if (NotAfter > signer.NotAfter) {
                NotAfter = signer.NotAfter;
            }
        }
    }
    // generates SKI and optionally AKI
    void generateKeyIdentifiers(X509Certificate2 signer) {
        using (var hasher = SHA1.Create()) {
            var hash = hasher.ComputeHash(PrivateKeyInfo.GetPublicKey().EncodedKeyValue.RawData);
            var ext = new X509SubjectKeyIdentifierExtension(hash, false);
            _extensions.Add(ext);
        }
        if (signer != null) {
            var ext = new X509AuthorityKeyIdentifierExtension(signer, AuthorityKeyIdentifierType.KeyIdentifier, false);
            _extensions.Add(ext);
        }
    }
    void processExtensions() {
        foreach (X509Extension extension in Extensions) {
            if (_excludedExtensions.Contains(extension.Oid.Value)) {
                continue;
            }
            _extensions.Add(extension.ConvertExtension());
        }
        finalExtensions = new X509ExtensionCollection();
        foreach (var extension in _extensions) {
            finalExtensions.Add(extension);
        }
    }
    void preGenerate(X509Certificate2 signer) {
        PrivateKeyInfo.Create();
        generateSerialNumber();
        validateDates(signer);
        generateKeyIdentifiers(signer);
        processExtensions();
    }
    void setFriendlyName(X509Certificate2 cert) {
        if (String.IsNullOrWhiteSpace(FriendlyName)) {
            return;
        }
        Byte[] stringBytes = Encoding.Unicode.GetBytes(FriendlyName + "\0");
        IntPtr ptr = Marshal.AllocHGlobal(stringBytes.Length);
        Marshal.Copy(stringBytes, 0, ptr, stringBytes.Length);
        var blob = new Wincrypt.CRYPTOAPI_BLOB {
            cbData = (UInt32)stringBytes.Length,
            pbData = ptr
        };
        IntPtr blobPtr = Marshal.AllocHGlobal(Marshal.SizeOf(blob));
        Marshal.StructureToPtr(blob, blobPtr, false);
        Crypt32.CertSetCertificateContextProperty(cert.Handle, X509CertificatePropertyType.FriendlyName, 0, blobPtr);
        Marshal.FreeHGlobal(ptr);
        Marshal.FreeHGlobal(blobPtr);
    }
    void postGenerate(X509Certificate2 cert) {
        // write key info to cert property
        var keyInfo = new Wincrypt.CRYPT_KEY_PROV_INFO {
            pwszProvName = PrivateKeyInfo.ProviderName,
            dwProvType = PrivateKeyInfo.ProviderType,
            pwszContainerName = PrivateKeyInfo.KeyContainerName,
            dwKeySpec = PrivateKeyInfo.KeySpec
        };
        if (PrivateKeyInfo.MachineContext) {
            keyInfo.dwFlags = nCrypt2.NCRYPT_MACHINE_KEY_FLAG;
        }
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(keyInfo));
        Marshal.StructureToPtr(keyInfo, ptr, false);
        Crypt32.CertSetCertificateContextProperty(cert.Handle, X509CertificatePropertyType.ProviderInfo, 0, ptr);
        Marshal.FreeHGlobal(ptr);
        PrivateKeyInfo.Dispose();
        // friendly name
        setFriendlyName(cert);
    }
    X509Certificate2 build(X509Certificate2 signer) {
        MessageSigner signerInfo = signer == null
            ? new MessageSigner(PrivateKeyInfo, HashingAlgorithm)
            : new MessageSigner(signer, HashingAlgorithm);
        signerInfo.PaddingScheme = AlternateSignatureFormat
            ? SignaturePadding.PSS
            : SignaturePadding.PKCS1;
        // initialize from v3 version
        var rawData = new List<Byte>(_versionBytes);
        // serial number
        rawData.AddRange(Asn1Utils.Encode(serialNumber, (Byte)Asn1Type.INTEGER));
        // algorithm identifier
        rawData.AddRange(signerInfo.GetAlgorithmIdentifier(AlternateSignatureFormat).RawData);
        // issuer
        rawData.AddRange(signer == null
            ? SubjectName.RawData
            : signer.SubjectName.RawData);
        // NotBefore and NotAfter
        List<Byte> date = Asn1Utils.EncodeDateTime(NotBefore).ToList();
        date.AddRange(Asn1Utils.EncodeDateTime(NotAfter));
        rawData.AddRange(Asn1Utils.Encode(date.ToArray(), 48));
        // subject
        rawData.AddRange(SubjectName.RawData);
        rawData.AddRange(PrivateKeyInfo.GetPublicKey().Encode());
        rawData.AddRange(Asn1Utils.Encode(finalExtensions.Encode(), 0xa3));
        var blob = new SignedContentBlob(Asn1Utils.Encode(rawData.ToArray(), 48), ContentBlobType.ToBeSignedBlob);
        blob.Sign(signerInfo);
        return new X509Certificate2(blob.Encode());
    }

    /// <summary>
    /// Creates, signs and encodes certificate object.
    /// </summary>
    /// <param name="signer">Optional signer certificate. If null, a self-signed certificate is generated.</param>
    /// <returns>A signed certificate.</returns>
    public X509Certificate2 Build(X509Certificate2 signer = null) {
        preGenerate(signer);
        X509Certificate2 cert = build(signer);
        postGenerate(cert);
        return cert;
    }
}