using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.Win32;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices;
/// <summary>
/// Represents a Certification Authority cryptography configuration which determines which provider and algorithms to use when
/// CA server signs certificates and certificate revocation lists (CRLs).
/// </summary>
public class CACryptography {
    String ConfigString;
    Boolean alternateSignatureAlgorithm;
    Oid publicKeyAlgorithm, hashingAlgorithm;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    public CACryptography(CertificateAuthority certificateAuthority) {
        if (certificateAuthority == null) { throw new ArgumentNullException(nameof(certificateAuthority)); }
        if (String.IsNullOrEmpty(certificateAuthority.Name)) { throw new UninitializedObjectException(); }
        m_initialize(certificateAuthority);
    }

    /// <summary>
    /// Gets the common name of the Certification Authority in a sanitized form as specified in
    /// <see href="http://msdn.microsoft.com/en-us/library/cc249826(PROT.10).aspx">MS-WCCE §3.1.1.4.1.1</see>.
    /// </summary>
    public String Name { get; private set; }
    /// <summary>
    /// Gets the display name of the Certification Authority (sanitized characters are decoded to textual characters).
    /// </summary>
    public String DisplayName { get; private set; }
    /// <summary>
    /// Gets the host fully qualified domain name (FQDN) of the server where Certification Authority is installed.
    /// </summary>
    public String ComputerName { get; private set; }
    /// <summary>
    /// Gets or sets the public key algorithm (such as RSA) that is used for signing purposes.
    /// </summary>
    /// <remarks>If <see cref="ProviderIsCNG"/> property is set to <strong>False</strong>, setter is ignored.</remarks>
    public Oid PublicKeyAlgorithm {
        get { return publicKeyAlgorithm; }
        set {
            if (!ProviderIsCNG && publicKeyAlgorithm != null && value.Value == publicKeyAlgorithm.Value) { return; }
            publicKeyAlgorithm = value;
            IsModified = true;
        }
    }
    /// <summary>
    /// Gets or sets the hashing algorithm that is used for signing purposes.
    /// </summary>
    public Oid HashingAlgorithm {
        get { return hashingAlgorithm; }
        set {
            if (hashingAlgorithm != null && value.Value == hashingAlgorithm.Value || !validateHashAlgorithm(value.Value)) { return; }
            hashingAlgorithm = value;
            IsModified = true;
        }
    }
    /// <summary>
    /// Gets provider name that is used by a Certification Authority installation.
    /// </summary>
    public String ProviderName { get; private set; }
    /// <summary>
    /// Gets or sets the value that indicates whether the CA server supports alternate signature algorithms (PKCS#1 v2.1)
    /// </summary>
    /// <remarks>If <see cref="ProviderIsCNG"/> property is set to <strong>False</strong>, setter is ignored.</remarks>
    public Boolean AlternateSignatureAlgorithm {
        get { return alternateSignatureAlgorithm; }
        set {
            if (value == alternateSignatureAlgorithm && !ProviderIsCNG) { return; }
            alternateSignatureAlgorithm = value;
            IsModified = true;
        }
    }
    /// <summary>
    /// Specifies whether the CA uses CNG (or legacy) cryptographic service provider.
    /// </summary>
    public Boolean ProviderIsCNG { get; set; }
    /// <summary>
    /// Indiciates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        ConfigString = certificateAuthority.ConfigString;
        if (CryptoRegistry.Ping(ComputerName)) {
            ProviderIsCNG = (Int32)CryptoRegistry.GetRReg("ProviderType", $@"{Name}\CSP", ComputerName) == 0;
            ProviderName = (String)CryptoRegistry.GetRReg("Provider", $@"{Name}\CSP", ComputerName);
            publicKeyAlgorithm = ProviderIsCNG
                ? new Oid((String)CryptoRegistry.GetRReg("CNGPublicKeyAlgorithm", $@"{Name}\CSP", ComputerName))
                : new Oid("1.2.840.113549.1.1.1"); // rsa
            if (ProviderIsCNG) {
                // CNG
                hashingAlgorithm = new Oid((String)CryptoRegistry.GetRReg("CNGHashAlgorithm", $@"{Name}\CSP", ComputerName));
                try {
                    Int32 altName = (Int32)CryptoRegistry.GetRReg("AlternateSignatureAlgorithm", $@"{Name}\CSP", ComputerName);
                    alternateSignatureAlgorithm = altName != 0;
                } catch {
                    alternateSignatureAlgorithm = false;
                }
            } else {
                // legacy
                Int32 algId = (Int32)CryptoRegistry.GetRReg("HashAlgorithm", $@"{Name}\CSP", ComputerName);
                hashingAlgorithm = getOidFromValue(algId);
            }
            return;
        }
        ProviderIsCNG = (Int32)CryptoRegistry.GetRegFallback(ConfigString, "CSP", "ProviderType") == 0;
        ProviderName = (String)CryptoRegistry.GetRegFallback(ConfigString, "CSP", "Provider");
        publicKeyAlgorithm = ProviderIsCNG
            ? new Oid((String)CryptoRegistry.GetRegFallback(ConfigString, "CSP", "CNGPublicKeyAlgorithm"))
            : new Oid("1.2.840.113549.1.1.1"); // rsa
        if (ProviderIsCNG) {
            hashingAlgorithm = new Oid((String)CryptoRegistry.GetRegFallback(ConfigString, "CSP", "CNGHashAlgorithm"));
        } else {
            Int32 algId = (Int32)CryptoRegistry.GetRegFallback(ConfigString, "CSP", "HashAlgorithm");
            hashingAlgorithm = getOidFromValue(algId);
        }
        if (ProviderIsCNG) {
            try {
                alternateSignatureAlgorithm = (Int32)CryptoRegistry.GetRegFallback(ConfigString, "CSP", "AlternateSignatureAlgorithm") != 0;
            } catch {
                alternateSignatureAlgorithm = false;
            }
        }
    }
    static Oid getOidFromValue(Int32 algId) {
        switch (algId) {
            case 0x8001: return new Oid("1.2.840.113549.2.2");      // md2
            case 0x8003: return new Oid("1.2.840.113549.2.5");      // md5
            case 0x8004: return new Oid("1.3.14.3.2.26");           // sha1
            case 0x8012: return new Oid("2.16.840.1.101.3.4.2.1");  // sha256
            case 0x8013: return new Oid("2.16.840.1.101.3.4.2.2");  // sha384
            case 0x8014: return new Oid("2.16.840.1.101.3.4.2.3");  // sha512
            default: return null;
        }
    }
    static Int32 getValueFromOid(Oid oid) {
        switch (oid.Value) {
            case "1.2.840.113549.2.2": return 0x8001;
            case "1.2.840.113549.2.5": return 0x8003;
            case "1.3.14.3.2.26": return 0x8004;
            case "2.16.840.1.101.3.4.2.1": return 0x8012;
            case "2.16.840.1.101.3.4.2.2": return 0x8013;
            case "2.16.840.1.101.3.4.2.3": return 0x8014;
            default: return 0;
        }
    }
    static Boolean validateHashAlgorithm(String value) {
        return new List<String> {
                                        "1.2.840.113549.2.2",
                                        "1.2.840.113549.2.5",
                                        "1.3.14.3.2.26",
                                        "2.16.840.1.101.3.4.2.1",
                                        "2.16.840.1.101.3.4.2.2",
                                        "2.16.840.1.101.3.4.2.3"
                                    }.Contains(value);
    }

    /// <summary>
    /// Updates CA server cryptography settings by writing them to Certification Authority.
    /// </summary>
    /// <param name="restart">
    ///        Indiciates whether to restart certificate services to immediately apply changes. Updated settings has no effect
    ///        until CA service is restarted.
    /// </param>
    /// <exception cref="ServerUnavailableException">
    ///        The target CA server could not be contacted via remote registry and RPC protocol.
    /// </exception>
    /// <returns>
    ///        <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
    ///        and the method returns <strong>False</strong>.
    /// </returns>
    /// <remarks>
    ///        The caller must have <strong>Administrator</strong> permissions on the target CA server.
    /// </remarks>
    public Boolean SetInfo(Boolean restart) {
        if (!IsModified) { return false; }
        if (CryptoRegistry.Ping(ComputerName)) {
            if (ProviderIsCNG) {
                CryptoRegistry.SetRReg(publicKeyAlgorithm.FriendlyName, "CNGPublicKeyAlgorithm", RegistryValueKind.String, Name + "\\CSP", ComputerName);
                CryptoRegistry.SetRReg(hashingAlgorithm.FriendlyName, "CNGHashAlgorithm", RegistryValueKind.String, Name + "\\CSP", ComputerName);
                if (alternateSignatureAlgorithm) {
                    CryptoRegistry.SetRReg(1, "AlternateSignatureAlgorithm", RegistryValueKind.String, $@"{Name}\CSP", ComputerName);
                } else {
                    CryptoRegistry.SetRReg(0, "AlternateSignatureAlgorithm", RegistryValueKind.DWord, $@"{Name}\CSP", ComputerName);
                }
            } else {
                CryptoRegistry.SetRReg(getValueFromOid(hashingAlgorithm), "HashAlgorithm", RegistryValueKind.DWord, $@"{Name}\CSP", ComputerName);
            }
        } else {
            if (CertificateAuthority.Ping(ComputerName)) {
                if (ProviderIsCNG) {
                    CryptoRegistry.SetRegFallback(ConfigString, "CSP", "CNGPublicKeyAlgorithm", publicKeyAlgorithm.FriendlyName);
                    CryptoRegistry.SetRegFallback(ConfigString, "CSP", "CNGHashAlgorithm", hashingAlgorithm.FriendlyName);
                    CryptoRegistry.SetRegFallback(ConfigString, "CSP", "CNGHashAlgorithm", alternateSignatureAlgorithm ? 1 : 0);
                } else {
                    CryptoRegistry.SetRegFallback(ConfigString, "CSP", "HashAlgorithm", getValueFromOid(hashingAlgorithm));
                }
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
        if (restart) { CertificateAuthority.Restart(ComputerName); }
        IsModified = false;
        return true;
    }
}
