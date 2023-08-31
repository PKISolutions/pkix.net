using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Defines ADCS Certification Authority internal audit settings.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum CertSrvAuditFlags {
    /// <summary>
    /// No audit is performed on CA server.
    /// </summary>
    None               = 0,
    /// <summary>
    /// Audit start/stop of the service.
    /// </summary>
    StartAndStop       = 1,
    /// <summary>
    /// Audit operations associated with backup/restore of the CA database.
    /// </summary>
    BackupAndRestore   = 2,
    /// <summary>
    /// Audit operations associated with certificate issuance.
    /// </summary>
    CertificateIssued  = 4,
    /// <summary>
    /// Audit operations associated with certificate revocation.
    /// </summary>
    CertificateRevoked = 8,
    /// <summary>
    /// Audit changes to the security settings on the Certification Authority service.
    /// </summary>
    SecurityChange     = 0x10,
    /// <summary>
    /// Audit operations associated with Key Recovery.
    /// </summary>
    KeyRecovery        = 0x20,
    /// <summary>
    /// Audit operations associated with changes in CA configuration.
    /// </summary>
    ConfigChange       = 0x40,
    /// <summary>
    /// Audit all operations on CA server.
    /// </summary>
    All                = StartAndStop | BackupAndRestore | CertificateIssued | CertificateRevoked | SecurityChange | KeyRecovery | ConfigChange
}