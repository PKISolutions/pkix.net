using System;
using System.Linq;
using Microsoft.Win32;
using SysadminsLV.PKI.Exceptions;
using SysadminsLV.PKI.Management.CertificateServices;
using SysadminsLV.PKI.Utils;

namespace PKI.CertificateServices.Flags;
/// <summary>
/// Contains information about interface flags enabled on CA server. These settings affect CA management (<strong>ICertAdmin</strong>)
/// and enrollment (<strong>ICertRequest</strong>) interfaces.
/// </summary>
public class InterfaceFlag {
    String configString;
    CertSrvPlatformVersion version;

    /// <param name="certificateAuthority">Specifies an existing <see cref="CertificateAuthority"/> object.</param>
    /// <exception cref="UninitializedObjectException">An object in the <strong>certificateAuthority</strong> parameter is not initialized.</exception>
    public InterfaceFlag(CertificateAuthority certificateAuthority) {
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
    /// Gets enabled interface flags. Possible flags are listed in <see cref="InterfaceFlagEnum"/>.
    /// </summary>
    public InterfaceFlagEnum InterfaceFlags { get; private set; }
    /// <summary>
    /// Indicates whether the object was modified after it was instantiated.
    /// </summary>
    public Boolean IsModified { get; private set; }

    void m_initialize(CertificateAuthority certificateAuthority) {
        Name = certificateAuthority.Name;
        DisplayName = certificateAuthority.DisplayName;
        ComputerName = certificateAuthority.ComputerName;
        configString = certificateAuthority.ConfigString;
        version = certificateAuthority.Version;
        if (CryptoRegistry.Ping(ComputerName)) {
            InterfaceFlags = (InterfaceFlagEnum)CryptoRegistry.GetRReg("InterfaceFlags", Name, ComputerName);
        } else {
            if (CertificateAuthority.Ping(ComputerName)) {
                InterfaceFlags = (InterfaceFlagEnum)CryptoRegistry.GetRegFallback(configString, "", "InterfaceFlags");
            } else {
                ServerUnavailableException e = new ServerUnavailableException(DisplayName);
                e.Data.Add(nameof(e.Source), (OfflineSource)3);
                throw e;
            }
        }
    }

    /// <summary>
    /// Adds management interface flags to enable on a specified Certification Authority. Multiple
    /// flags can be added at the time.
    /// </summary>
    /// <param name="flags">One or more flags defined in <see cref="InterfaceFlagEnum"/> enumeration.</param>
    public void Add(InterfaceFlagEnum flags) {
        Int32[] existing = EnumFlags.GetEnabled(typeof(InterfaceFlagEnum),(Int32)InterfaceFlags);
        Int32[] newf = EnumFlags.GetEnabled(typeof(InterfaceFlagEnum), (Int32)flags);
        foreach (Int32 item in newf.Where(item => !EnumFlags.Contains(existing, item))) {
            InterfaceFlags = (InterfaceFlagEnum)((Int32)InterfaceFlags + item);
            IsModified = true;
        }
    }
    /// <summary>
    /// Removes management interface flags from a specified Certification Authority. Multiple
    /// flags can be removed at the time.
    /// </summary>
    /// <param name="flags">One or more flags defined in <see cref="InterfaceFlagEnum"/> enumeration.</param>
    public void Remove(InterfaceFlagEnum flags) {
        Int32[] existing = EnumFlags.GetEnabled(typeof(InterfaceFlagEnum), (Int32)InterfaceFlags);
        Int32[] newf = EnumFlags.GetEnabled(typeof(InterfaceFlagEnum), (Int32)flags);
        foreach (Int32 item in newf.Where(item => EnumFlags.Contains(existing, item))) {
            InterfaceFlags = (InterfaceFlagEnum)((Int32)InterfaceFlags - item);
            IsModified = true;
        }
    }
    /// <summary>
    /// Restores default management interface flags on a specified Certification Authority. The method do not
    /// writes default flags to a configuration. After calling this method call <see cref="SetInfo"/> method to write
    /// the values to a configuration.
    /// </summary>
    /// <remarks>The following default flags are defined depending on an operating system:
    /// <list type="table">
    /// <listheader>
    /// <term>Operating system</term>
    /// <description>Default flags</description>
    /// </listheader>
    /// <item>
    /// <term><list type="bullet">
    /// <item>Windows 2000 Server</item>
    /// <item>Windows Server 2003, Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008, Standard, Enterprise, Datacenter editions</item>
    /// <item>Windows Server 2008 R2, Standard, Enterprise, Datacenter editions</item>
    /// </list></term>
    /// <description><list type="bullet">
    /// <item><strong>NoRemoteICertAdminBackup</strong></item>
    /// </list>
    /// </description>
    /// </item>
    /// <item>
    /// <term><list type="bullet">
    /// <item>Windows Server 2012 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2012 R2 Foundation, Essentials, Standard, Datacenter editions</item>
    /// <item>Windows Server 2016 Essentials, Standard, Datacenter editions</item>
    /// </list></term>
    /// <description><list type="bullet">
    /// <item><strong>LockICertRequest</strong></item>
    /// <item><strong>NoRemoteICertAdminBackup</strong></item>
    /// <item><strong>EnforceEncryptICertRequest</strong></item>
    /// <item><strong>EnforceEncryptICertAdmin</strong></item>
    /// </list>
    /// </description>
    /// </item>
    /// </list>
    /// </remarks>
    public void Restore() {
        switch (version) {
            case CertSrvPlatformVersion.Win2000:
            case CertSrvPlatformVersion.Win2003:
            case CertSrvPlatformVersion.Win2008:
            case CertSrvPlatformVersion.Win2008R2: InterfaceFlags = InterfaceFlagEnum.NoRemoteICertAdminBackup; break;
            case CertSrvPlatformVersion.Win2012:
            case CertSrvPlatformVersion.Win2012R2:
            case CertSrvPlatformVersion.Win2016:
                InterfaceFlags = InterfaceFlagEnum.NoRemoteICertAdminBackup |
                                 InterfaceFlagEnum.EnforceEncryptICertAdmin |
                                 InterfaceFlagEnum.EnforceEncryptICertRequest |
                                 InterfaceFlagEnum.LockICertRequest;

                break;
            default: InterfaceFlags = InterfaceFlagEnum.NoRemoteICertAdminBackup; break;
        }
        IsModified = true;
    }
    /// <summary>
    /// Updates management interface flags by writing them to Certification Authority.
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
                CryptoRegistry.SetRReg((Int32)InterfaceFlags, "InterfaceFlags", RegistryValueKind.DWord, Name, ComputerName);
                if (restart) { CertificateAuthority.Restart(ComputerName); }
                IsModified = false;
                return true;
            }
            if (CertificateAuthority.Ping(ComputerName)) {
                CryptoRegistry.SetRegFallback(configString, String.Empty, "InterfaceFlags", (Int32)InterfaceFlags);
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
