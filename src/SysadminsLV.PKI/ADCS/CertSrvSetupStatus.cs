using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Gets the status of the Certification Authority installation.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertSrvSetupStatus {
    /// <summary>
    /// Setup status cannot be determined.
    /// </summary>
    Unknown                  = 0x00000000, // 0
    /// <summary>
    /// Server is installed.
    /// </summary>
    ServerInstall            = 0x00000001, // 1
    /// <summary>
    /// Client is installed.
    /// </summary>
    ClientInstall            = 0x00000002, // 2
    /// <summary>
    /// Certification Authority installation is incomplete. This value indicates that subordinate CA is installed and awaits CA
    /// certificate installation (in the case with offline parent CA). CA service will not start until installation is completed.
    /// </summary>
    Incomplete               = 0x00000004, // 4
    /// <summary>
    /// Subordinate CA has requested certificate renewal and awaits new CA certificate installation. CA can run in normal mode and issue
    /// certificates to clients.
    /// </summary>
    RenewalPending           = 0x00000008, // 8
    /// <summary>
    /// CA certificate request was sent to a online parent CA.
    /// </summary>
    OnlineRenewalPending     = 0x00000010, // 16
    /// <summary>
    /// CA certificate request was denied by a online parent CA.
    /// </summary>
    OnlineRenewalDenied      = 0x00000020, // 32
    /// <summary>
    /// Create new database.
    /// </summary>
    CreateDB                 = 0x00000040, // 64
    /// <summary>
    /// Attempt to create "vroot" (enrollment web pages) virtual directory.
    /// </summary>
    AttemptVRootCreate        = 0x00000080, // 128
    /// <summary>
    /// Force new CRL(s).
    /// </summary>
    ForceCRL                 = 0x00000100, // 256
    /// <summary>
    /// Add server type to CA DS object "flags" attribute.
    /// </summary>
    UpdateCAObjectSvrType    = 0x00000200, // 512
    /// <summary>
    /// CA server was upgraded.
    /// </summary>
    ServerUpgraded           = 0x00000400, // 1024
    /// <summary>
    /// Certification Authority was upgraded from Windows 2000 Server and awaits for security upgrade.
    /// </summary>
    SecurityUpgradePending   = 0x00000800, // 2048
    /// <summary>
    /// Permissions changed while the CA was down and the CA will need to update the directory service when it restarts.
    /// </summary>
    PermissionsUpdatePending = 0x00001000, // 4096
    /// <summary>
    /// Windows Server 2003 SP1 - global DCOM security has been fixed.
    /// </summary>
    SecurityUpgraded         = 0x00002000, // 8192
    /// <summary>
    /// Server is up to date.
    /// </summary>
    ServerIsUpToDate         = 0x00004000 // 16384
}