using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Interop.CERTENROLLLib;
using PKI.Utils;
using SysadminsLV.Asn1Parser.Universal;
using SysadminsLV.PKI.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a managed X.509 private key generator.
/// </summary>
public class X509PrivateKeyBuilder : IKeyStorageInfo, IDisposable {
    readonly IX509PrivateKey _keyGen = new CX509PrivateKeyClass();

    /// <summary>
    /// Gets or sets a legacy cryptographic service provider (CSP) or CNG key storage provider (KSP).
    /// </summary>
    public String ProviderName {
        get => _keyGen.ProviderName;
        set {
            _keyGen.ProviderName = value;
            // ProviderType is necessary when creating CSP params to associate key with cert.
            // Windows Vista and Windows Server 2008 do not set ProviderType property and getter
            // on ProviderType will throw exception. So we test if getter throws exception:
            try {
                X509ProviderType temp = _keyGen.ProviderType;
            } catch {
                // if it does, get specified provider object
                CspProviderInfo csp = CspProviderInfoCollection.GetProviderInfo(_keyGen.ProviderName);
                if (csp != null) {
                    // and explicitly set ProviderType value from CSP object.
                    _keyGen.ProviderType = (X509ProviderType)csp.Type;
                }
            }
        }
    }
    /// <summary>
    /// Gets provider type. Provider type is cryptographic service provider family and is used only with legacy
    /// CSP. This member is automatically populated after invoking <see cref="Create"/> method.
    /// </summary>
    public Int32 ProviderType => (Int32)_keyGen.ProviderType;
    /// <summary>
    /// Gets or sets key container name that is used to store the key material within key provider.
    /// </summary>
    public String KeyContainerName {
        get => _keyGen.ContainerName;
        set => _keyGen.ContainerName = value;
    }
    /// <summary>
    /// Gets or sets public key algorithm. For CNG keys, key and curve name must be used. For example, "ECDSA_P256",
    /// "ECDH_brainpoolP320r1". When not set, default key algorithm for specified provider is used and depends on
    /// a particular cryptographic service provider (CSP or KSP).
    /// </summary>
    public Oid PublicKeyAlgorithm {
        get => new(_keyGen.Algorithm.Value);
        set {
            var coid = new CObjectIdClass();
            coid.InitializeFromValue(value.Value);
            _keyGen.Algorithm = coid;
        }
    }
    /// <summary>
    /// Gets or sets a value that identifies whether a private key can be used for signing, or encryption, or both.
    /// </summary>
    public X509KeySpecFlags KeySpec {
        get => (X509KeySpecFlags)_keyGen.KeySpec;
        set => _keyGen.KeySpec = (X509KeySpec)value;
    }
    /// <summary>
    /// Gets or sets asymmetric public key length in bits. For elliptic curve cryptography (ECC), this member
    /// is automatically populated from <see cref="PublicKeyAlgorithm"/> member value, because ECC curve
    /// includes key length.
    /// </summary>
    public Int32 KeyLength {
        get => _keyGen.Length;
        set => _keyGen.Length = value;
    }
    /// <summary>
    /// Gets or sets the flag that indicates whether the private key is exportable or not. For hardware providers,
    /// this flag is set to <strong>False</strong> and cannot be modified.
    /// </summary>
    public Boolean Exportable {
        get => _keyGen.ExportPolicy == X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG
               || _keyGen.ExportPolicy == X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        set => _keyGen.ExportPolicy = value
            ? X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG | X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
            : X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;

    }
    /// <summary>
    /// Gets or sets private key protection options when the key is accessded.
    /// </summary>
    public X509PrivateKeyProtection KeyProtection {
        get => _keyGen.KeyProtection;
        set => _keyGen.KeyProtection = value;
    }
    /// <summary>
    /// Gets or sets the value that indicates whether the key is stored in machine or current user context.
    /// </summary>
    public Boolean MachineContext {
        get => _keyGen.MachineContext;
        set => _keyGen.MachineContext = value;
    }
    /// <summary>
    /// Gets or sets an access control list to private key in a SDDL form.
    /// </summary>
    public String SecurityDescriptor {
        get => _keyGen.SecurityDescriptor;
        set => _keyGen.SecurityDescriptor = value;
    }

    /// <summary>
    /// Gets public portion of the key pair.
    /// </summary>
    /// <returns>An instance of <see cref="PublicKey"/> class with public key.</returns>
    public PublicKey GetPublicKey() {
        Oid algorithm = PublicKeyAlgorithm.FriendlyName.StartsWith("EC", StringComparison.OrdinalIgnoreCase)
            ? new Oid(AlgorithmOid.ECC)
            : PublicKeyAlgorithm;
        CX509PublicKey pubKey = _keyGen.ExportPublicKey();
        var key = new AsnEncodedData(algorithm, Convert.FromBase64String(pubKey.EncodedKey));
        Byte[] paramBytes;
        try {
            paramBytes = Convert.FromBase64String(pubKey.EncodedParameters);
        } catch {
            paramBytes = new Asn1Null().RawData;
        }
        var param = new AsnEncodedData(algorithm, paramBytes);
        CryptographyUtils.ReleaseCom(pubKey);
        return new PublicKey(algorithm, param, key);
    }
    /// <summary>
    /// Creates a new asymmetric key pair based on a current configuration. If the method succeeds, all properties
    /// of this object are read-only and will throw exception when setter accessor is accessed.
    /// </summary>
    public void Create() {
        _keyGen.Create();
    }
    /// <summary>
    /// Deletes generated private key material from key storage. For software-based providers, the key is deleted
    /// from file system, for hardware-based providers, the key is deleted from hardware. When hardware-based
    /// provider is used, a PIN prompt dialog may appear.
    /// </summary>
    public void Delete() {
        _keyGen.Delete();
    }

    #region IDisposable
    void releaseUnmanagedResources() {
        if (_keyGen.Opened) {
            _keyGen.Close();
        }
        CryptographyUtils.ReleaseCom(_keyGen);
    }
    /// <inheritdoc />
    public void Dispose() {
        releaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }
    /// <inheritdoc />
    ~X509PrivateKeyBuilder() {
        releaseUnmanagedResources();
    }
    #endregion
}