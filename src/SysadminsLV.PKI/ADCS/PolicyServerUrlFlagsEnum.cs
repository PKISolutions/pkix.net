using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// The <strong>PolicyServerFlagsEnum</strong> enumeration contains certificate enrollment policy (CEP) server flags
/// </summary>
[Flags]
public enum PolicyServerUrlFlagsEnum {
    /// <summary>
    /// No flags are specified.
    /// </summary>
    None                  = 0,
    /// <summary>
    /// Policy information is specified in group policy by an administrator.
    /// </summary>
    LocationGroupPolicy   = 1,
    /// <summary>
    /// Policy information is specified in the registry.
    /// </summary>
    LocationRegistry      = 2,
    /// <summary>
    /// Specifies that certificate enrollments and renewals include client specific data in a ClientId attribute. Examples include
    /// the name of the cryptographic service provider, the Windows version number, the user name, the computer DNS name, and the
    /// domain controller DNS name. This flag can be set by group policy.
    /// <para>This flag has been included to address privacy concerns that can arise during enrollment to servers that are managed
    /// by administrators other than those who manage the forest in which the user resides. By not setting this flag, you can prevent
    /// sending personal information to non-local administrators.</para>
    /// </summary>
    UseClientId           = 4,
    /// <summary>
    /// Automatic certificate enrollment is enabled.
    /// </summary>
    AutoEnrollmentEnabled = 16,
    /// <summary>
    /// Specifies that the certificate of the issuing CA need not be trusted by the client to install a certificate signed by the CA.
    /// </summary>
    AllowUnTrustedCA      = 32,
}