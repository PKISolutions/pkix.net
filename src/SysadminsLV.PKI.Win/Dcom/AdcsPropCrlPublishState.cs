using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Contains enumeration values for CRL publication status used by <see cref="ICertPropReaderD"/> interface.
    /// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
    /// </summary>
    [Flags]
    public enum AdcsPropCrlPublishState {
        /// <summary>
        /// A base CRL was published.
        /// </summary>
        Base                   = 0x00000001,
        /// <summary>
        /// A delta CRL was published.
        /// </summary>
        Delta                  = 0x00000002,
        /// <summary>
        /// A complete CRL was published.
        /// </summary>
        Complete               = 0x00000004,
        /// <summary>
        /// A blank delta CRL with new delta CRL indicator extension (CRL_Min_Base value). 
        /// </summary>
        Shadow                 = 0x00000008,
        /// <summary>
        /// An error occurred when publishing the generated CRL to the default local registry location.
        /// </summary>
        CaStoreError           = 0x00000010,
        /// <summary>
        /// A URL is not valid.
        /// </summary>
        BadUrlError            = 0x00000020,
        /// <summary>
        /// A CRL was published manually.
        /// </summary>
        Manual                 = 0x00000040,
        /// <summary>
        /// An error occurred when verifying the signature of the generated CRL prior to attempting to publish the CRL.
        /// </summary>
        SignatureError         = 0x00000080,
        /// <summary>
        /// The CA encountered an error trying to write the CRL to an LDAP location.
        /// </summary>
        LdapError              = 0x00000100,
        /// <summary>
        /// A file error prevented publication.
        /// </summary>
        FileError              = 0x00000200,
        /// <summary>
        /// An FTP URI was encountered during publishing of the CRL.
        /// <para><strong>Note:</strong> The Windows CA does not write to ftp:// locations, so any ftp:// CRL publish attempt will cause this flag.</para>
        /// </summary>
        FtpError               = 0x00000400,
        /// <summary>
        /// An HTTP URI was encountered during publishing of the CRL.
        /// <para><strong>Note:</strong> The Windows CA does not write to http:// locations, so any http:// CRL publish attempt will cause this flag.</para>
        /// </summary>
        HttpError              = 0x00000800,
        /// <summary>
        /// Postponed publishing a delta CRL due to a failure in publishing a base CRL to an ldap:/// location.
        /// </summary>
        PostponedBaseLdapError = 0x00001000,
        /// <summary>
        /// Postponed publishing a delta CRL due to a failure in publishing a base CRL to a file:// location.
        /// </summary>
        PostponedBaseFileError = 0x00002000,
        /// <summary>
        /// The property is unavailable.
        /// </summary>
        NotApplicable          = unchecked((Int32)0xffffffff)
    }
}