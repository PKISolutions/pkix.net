using System;
using System.Collections.Generic;
using System.Linq;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices;
/// <summary>
/// Represents Certification Authority (CA) object with configured Authority Information Access extension.
/// </summary>
public class AuthorityInformationAccess {
    String ConfigString;
    AIA[] m_aia;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    public AuthorityInformationAccess(CertificateAuthority certificateAuthority) {
        if (!String.IsNullOrEmpty(certificateAuthority.Name)) {
            m_initialize(certificateAuthority);
        } else { throw new UninitializedObjectException(); }
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
    /// Gets or sets an array of <see cref="AIA"/> objects. Each <see cref="AIA"/> object represents Authority Information Access
    /// URL and URL parameters.
    /// </summary>
    public AIA[] URI {
        get { return m_aia; }
        set {
            m_aia = value;
            IsModified = !String.IsNullOrEmpty(Name);
        }
    }
    /// <summary>
    /// Indiciates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        String[] urls;

        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        ConfigString = certificateAuthority.ConfigString;
        if (CryptoRegistry.Ping(ComputerName)) {
            urls = (String[])CryptoRegistry.GetRReg("CACertPublicationURLs", Name, ComputerName);
        } else {
            if (CertificateAuthority.Ping(ComputerName)) {
                urls = (String[])CryptoRegistry.GetRegFallback(ConfigString, String.Empty, "CACertPublicationURLs");
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
        m_aia = urls.Select(url => new AIA(url)).ToArray();
    }

    /// <summary>
    /// Updates Authority Information Access configuration by writing them to Certification Authority.
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
                CryptoRegistry.SetRReg(strings, "CACertPublicationURLs", Name, ComputerName);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            if (CertificateAuthority.Ping(ComputerName)) {
                CryptoRegistry.SetRegFallback(ConfigString, String.Empty, "CACertPublicationURLs", strings);
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
