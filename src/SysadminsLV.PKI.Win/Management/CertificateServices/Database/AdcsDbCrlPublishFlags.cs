using System;

namespace SysadminsLV.PKI.Management.CertificateServices.Database;

/// <summary>
/// Contains enumeration values that represent CRL publish flags.
/// This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.
/// </summary>
// [MS-CSRA] §3.1.1.4.1
[Flags]
public enum AdcsDbCrlPublishFlags {
    /// <summary>
    /// None.
    /// </summary>
    None                    = 0,
    /// <summary>
    /// This is a Base CRL.
    /// </summary>
    BaseCRL                 = 0x1,
    /// <summary>
    /// This is a Delta CRL.
    /// </summary>
    DeltaCRL                = 0x2,
    /// <summary>
    /// The CRL published successfully.
    /// </summary>
    Complete                = 0x4,
    /// <summary>
    /// A blank delta CRL with new delta CRL indicator extension. When delta CRLs have just been disabled
    /// ('CRLDeltaPeriodUnits' config entry has just been set to 0), the CA publishes this type of CRL to
    /// force clients to retrieve a new base CRL.
    /// </summary>
    Shadow                  = 0x8,
    /// <summary>
    /// An error occurred when publishing the generated CRL to the default local registry location.
    /// </summary>
    CaStoreError            = 0x10,
    /// <summary>
    /// A URI that does not meet the format requirements (not valid file or LDAP URL) and an error was
    /// encountered during publishing of the CRL.
    /// </summary>
    BadUrlError             = 0x20,
    /// <summary>
    /// The CRL publication was manually requested by an administrator rather than by a CA on a schedule.
    /// </summary>
    Manual                  = 0x40,
    /// <summary>
    /// An error occurred when verifying the signature of the generated CRL prior to attempting to publish the CRL.
    /// </summary>
    SignatureError          = 0x80,
    /// <summary>
    /// The CA encountered an error trying to write the CRL to an LDAP location.
    /// </summary>
    LdapError               = 0x100,
    /// <summary>
    /// A file URI that does not meet the format requirements (not valid file URL) or CA encountered an error
    /// trying to write the CRL to a file location.
    /// </summary>
    FileError               = 0x200,
    /// <summary>
    /// An HTTP URI was encountered during publishing of the CRL. The Windows CA does not write to 'http://' locations,
    /// so any 'http://' CRL publish attempt will cause this flag.
    /// </summary>
    HttpError               = 0x800,
    /// <summary>
    /// An FTP URI was encountered during publishing of the CRL. The Windows CA does not write to 'ftp://' locations,
    /// so any 'ftp://' CRL publish attempt will cause this flag.
    /// </summary>
    FtpError                = 0x400,
    /// <summary>
    /// Postponed publishing a delta CRL due to a failure in publishing a base CRL to a 'ldap:///' location. For example,
    /// the Microsoft CA sends this flag with a call to publish a delta CRL when the corresponding base CRL could not be
    /// published to an LDAP location because of an error.
    /// </summary>
    PostponedLBaseLdapError = 0x1000,
    /// <summary>
    /// Postponed publishing a delta CRL due to a failure in publishing a base CRL to a 'file://' location. For example,
    /// the Microsoft CA sends this flag with a call to publish a delta CRL when the corresponding base CRL could not be
    /// published to a FILE location because of an error.
    /// </summary>
    PostponedBaseFileError  = 0x2000
}
