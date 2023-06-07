using System;
using System.Linq;
using Microsoft.Win32;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Management.CertificateServices;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices.Flags;
/// <summary>
/// Contains information about CRL flags enabled on CA server.
/// </summary>
public class CRLFlag {
    String configString;
    CertSrvPlatformVersion version;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    public CRLFlag(CertificateAuthority certificateAuthority) {
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
    /// Gets enabled CRL flags. Possible flags are listed in <see cref="CRLFlagEnum"/> enumeration.
    /// </summary>
    public CRLFlagEnum CRLFlags { get; private set; }
    /// <summary>
    /// Indiciates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        configString = certificateAuthority.ConfigString;
        version = certificateAuthority.Version;
        if (CryptoRegistry.Ping(ComputerName)) {
            CRLFlags = (CRLFlagEnum)CryptoRegistry.GetRReg("CRLFlags", Name, ComputerName);
        } else {
            if (CertificateAuthority.Ping(ComputerName)) {
                CRLFlags = (CRLFlagEnum)CryptoRegistry.GetRegFallback(configString, "", "CRLFlags");
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
    }

    /// <summary>
    /// Adds Certificate Revocation List (CRL) flags to enable on a specified Certification Authority. Multiple
    /// flags can be added at the time.
    /// </summary>
    /// <param name="flags">One or more flags defined in <see cref="CRLFlagEnum"/> enumeration.</param>
    /// <exception cref="ArgumentException">The data in the <strong>flags</strong> parameter
    /// contains Certificate Revocation List flags that are not supported by a current Certification Authority version.</exception>
    public void Add(CRLFlagEnum flags) {
        Int32[] existing = EnumFlags.GetEnabled(typeof(CRLFlagEnum), (Int32)CRLFlags);
        Int32[] newf = EnumFlags.GetEnabled(typeof(CRLFlagEnum), (Int32)flags);
        if (
            version == CertSrvPlatformVersion.Win2000 ||
            version == CertSrvPlatformVersion.Win2003 ||
            version == CertSrvPlatformVersion.Win2008 &&
            ((Int32)flags & (Int32)CRLFlagEnum.DisableChainVerification) != 0 ||
            ((Int32)flags & (Int32)CRLFlagEnum.BuildRootCACRLEntriesBasedOnKey) != 0) {
            throw new ArgumentException();
        }
        foreach (Int32 item in newf.Where(item => !EnumFlags.Contains(existing, item))) {
            CRLFlags = (CRLFlagEnum)((Int32)CRLFlags + item);
            IsModified = true;
        }
    }
    /// <summary>
    /// Removes Certificate Revocation List (CRL) flags from a specified Certification Authority. Multiple
    /// flags can be removed at the time.
    /// </summary>
    /// <param name="flags">One or more flags defined in <see cref="CRLFlagEnum"/> enumeration.</param>
    public void Remove(CRLFlagEnum flags) {
        Int32[] existing = EnumFlags.GetEnabled(typeof(CRLFlagEnum), (Int32)CRLFlags);
        Int32[] newf = EnumFlags.GetEnabled(typeof(CRLFlagEnum), (Int32)flags);
        foreach (Int32 item in newf.Where(item => EnumFlags.Contains(existing, item))) {
            CRLFlags = (CRLFlagEnum)((Int32)CRLFlags - item);
            IsModified = true;
        }
    }
    /// <summary>
    /// Restores default Certificate Revocation List flags on a specified Certification Authority. The method do not
    /// writes default flags to a configuration. After calling this method call <see cref="SetInfo"/> method to write
    /// the values to a configuration.
    /// </summary>
    /// <remarks>The following default flags are defined depending on an operating system:
    /// <list type="table">
    /// <listheader>
    ///        <term>Operating system</term>
    ///        <description>Default flags</description>
    /// </listheader>
    /// <item>
    ///        <term>
    ///            <list type="bullet">
    ///                <item>Windows 2000 Server</item>
    ///             <item>Windows Server 2003, Standard, Enterprise, Datacenter editions</item>
    ///             <item>Windows Server 2008, Standard, Enterprise, Datacenter editions</item>
    ///             <item>Windows Server 2008 R2, Standard, Enterprise, Datacenter editions</item>
    ///             <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    ///                <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    ///                <item>Windows Server 2016 Essentials, Standard, Datacenter editions</item>
    ///         </list>
    ///     </term>
    ///        <description>
    ///            <list type="bullet">
    ///                <item><strong>DeleteExpiredCRLs</strong></item>
    ///            </list>
    ///        </description>
    /// </item>
    /// </list>
    /// </remarks>
    public void Restore() {
        // currently only DeleteExpiredCRLs is enabled by default in every ADCS version.
        CRLFlags = CRLFlagEnum.DeleteExpiredCRLs;
        IsModified = true;
    }

    /// <summary>
    /// Updates Certificate Revocation List flags by writing them to Certification Authority.
    /// </summary>
    /// <param name="restart">
    /// Indicates whether to restart certificate services to immediately apply changes. Updated settings has no effect
    /// until CA service is restarted.
    /// </param>
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
            if (CryptoRegistry.Ping(ComputerName)) {
                CryptoRegistry.SetRReg((Int32)CRLFlags, "CRLFlags", RegistryValueKind.DWord, Name, ComputerName);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            if (CertificateAuthority.Ping(ComputerName)) {
                CryptoRegistry.SetRegFallback(configString, String.Empty, "CRLFlags", (Int32)CRLFlags);
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
