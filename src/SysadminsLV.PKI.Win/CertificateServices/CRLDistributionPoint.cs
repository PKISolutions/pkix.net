using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices;
/// <summary>
/// Represents Certification Authority (CA) object with configured CRL Distribution Points extension.
/// </summary>
public class CRLDistributionPoint {
    String ConfigString;
    CDP[] m_cdp;
    readonly Hashtable _variableValueMapping = new();
    Boolean[] keyMap;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    public CRLDistributionPoint(CertificateAuthority certificateAuthority) {
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
    /// Gets or sets an array of <see cref="CDP"/> objects. Each <see cref="CDP"/> object represents CRL Distribution Point
    /// URL and URL parameters.
    /// </summary>
    public CDP[] URI {
        get { return m_cdp; }
        set {
            m_cdp = value;
            IsModified = !String.IsNullOrEmpty(Name);
        }
    }
    /// <summary>
    /// Indiciates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        String[] urls;
        keyMap = certificateAuthority.GetKeyMap();
        buildVarValueMapping(certificateAuthority);
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        ConfigString = certificateAuthority.ConfigString;
        if (CryptoRegistry.Ping(ComputerName)) {
            urls = (String[])CryptoRegistry.GetRReg("CRLPublicationURLs", Name, ComputerName);
        } else {
            if (CertificateAuthority.Ping(ComputerName)) {
                urls = (String[])CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CRLPublicationURLs");
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
        m_cdp = urls.Select(url => new CDP(url)).ToArray();
        ResolveUrLs();
    }
    void ResolveUrLs() {
        if (keyMap == null || keyMap.Length < 1) { return; }
        foreach (CDP cdp in m_cdp) {
            List<String> resolved = new List<String>();
            for (Int32 index = 0; index < keyMap.Length; index++) {
                if (!keyMap[index]) { continue; }
                String str = (String)cdp.ConfigURI.Clone();
                str = str.Replace("<ServerDNSName>", (String)_variableValueMapping["<ServerDNSName>"])
                    .Replace("<ServerShortName>", (String)_variableValueMapping["<ServerShortName>"])
                    .Replace("<CaName>", (String)_variableValueMapping["<CaName>"])
                    .Replace("<ConfigurationContainer>", (String)_variableValueMapping["<ConfigurationContainer>"])
                    .Replace("<CATruncatedName>", (String)_variableValueMapping["<CATruncatedName>"])
                    .Replace("<DeltaCRLAllowed>", null)
                    .Replace("<CDPObjectClass>", (String)_variableValueMapping["<CDPObjectClass>"])
                    .Replace("<CAObjectClass>", (String)_variableValueMapping["<CAObjectClass>"]);
                str = index > 0
                    ? str.Replace("<CRLNameSuffix>", "(" + index + ")")
                    : str.Replace("<CRLNameSuffix>", null);
                resolved.Add(str);
                if (cdp.ConfigURI.Contains("<DeltaCRLAllowed>")) {
                    str = (String)cdp.ConfigURI.Clone();
                    str = str.Replace("<ServerDNSName>", (String)_variableValueMapping["<ServerDNSName>"])
                        .Replace("<ServerShortName>", (String)_variableValueMapping["<ServerShortName>"])
                        .Replace("<CaName>", (String)_variableValueMapping["<CaName>"])
                        .Replace("<ConfigurationContainer>", (String)_variableValueMapping["<ConfigurationContainer>"])
                        .Replace("<CATruncatedName>", (String)_variableValueMapping["<CATruncatedName>"])
                        .Replace("<DeltaCRLAllowed>", "+")
                        .Replace("<CDPObjectClass>", (String)_variableValueMapping["<CDPObjectClass>"])
                        .Replace("<CAObjectClass>", (String)_variableValueMapping["<CAObjectClass>"]);
                    if (cdp.UrlScheme == UrlProtocolSchemes.LDAP) {
                        str = str.Replace("certificateRevocationList", "deltaRevocationList");
                    }
                    str = index > 0
                        ? str.Replace("<CRLNameSuffix>", "(" + index + ")")
                        : str.Replace("<CRLNameSuffix>", null);
                    resolved.Add(str);
                }
            }
            cdp.ProjectedURI = resolved.ToArray();
        }
    }
    void buildVarValueMapping(CertificateAuthority ca) {
        _variableValueMapping.Add("<ServerDNSName>", ca.GetConfigEntry("ServerDNSName"));
        _variableValueMapping.Add("<ServerShortName>", ca.GetConfigEntry("ServerShortName"));
        _variableValueMapping.Add("<CaName>", ca.GetConfigEntry("CommonName"));
        _variableValueMapping.Add("<ConfigurationContainer>", ca.GetConfigEntry("ConfigurationContainer"));
        _variableValueMapping.Add("<CATruncatedName>", ca.GetConfigEntry("CATruncatedName"));
        _variableValueMapping.Add("<CRLNameSuffix>", ca.GetConfigEntry("ServerDNSName"));
        _variableValueMapping.Add("<DeltaCRLAllowed>", ca.GetConfigEntry("+"));
        _variableValueMapping.Add("<CDPObjectClass>", "?certificateRevocationList?base?objectClass=cRLDistributionPoint");
        _variableValueMapping.Add("<CAObjectClass>", "?cACertificate?base?objectClass=certificationAuthority");
    }

    /// <summary>
    /// Updates CRL Distribution Points configuration by writing them to Certification Authority.
    /// </summary>
    /// <param name="restart">Indiciates whether to restart certificate services to immediately apply changes. Updated settings has no effect until
    /// CA service is restarted.
    /// </param>
    /// <remarks>
    /// For this method to succeed, the caller must be granted CA <strong>Administrator</strong> permissions.
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">
    /// The caller do not have sufficient permissions to make changes in the CA configuration.
    /// </exception>
    /// <exception cref="ServerUnavailableException">
    /// The target CA server could not be contacted via remote registry and RPC protocol.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if configuration was changed. If an object was not modified since it was instantiated, configuration is not updated
    /// and the method returns <strong>False</strong>.
    /// </returns>
    /// <remarks>The caller must have <strong>Administrator</strong> permissions on the target CA server.</remarks>
    public Boolean SetInfo(Boolean restart) {
        if (IsModified) {
            List<String> strings = URI.Length > 0
                ? URI.Select(str => str.RegURI).ToList()
                : null;
            if (CryptoRegistry.Ping(ComputerName)) {
                CryptoRegistry.SetRReg(strings, "CRLPublicationURLs", Name, ComputerName);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            if (CertificateAuthority.Ping(ComputerName)) {
                CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CRLPublicationURLs", strings);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            ServerUnavailableException e = new ServerUnavailableException(DisplayName);
            e.Data.Add(nameof(e.Source), (OfflineSource)3);
            throw e;
        }
        return false;
    }
}
