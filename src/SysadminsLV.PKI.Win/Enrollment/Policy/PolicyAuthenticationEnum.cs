using System;

namespace PKI.Enrollment.Policy;
/// <summary>
/// This enumeration contains possible authentication methods used by Policy Web Service.
/// </summary>
[Obsolete("Use 'AdcsEnrollAuthenticationType'.")]
public enum PolicyAuthenticationEnum {
    /// <summary>
    /// Not used.
    /// </summary>
    None                = 0,
    /// <summary>
    /// Not used.
    /// </summary>
    Anonymous            = 1,
    /// <summary>
    /// Default
    /// </summary>
    Kerberos            = 2,
    /// <summary>
    /// 
    /// </summary>
    UserNameAndPassword    = 4,
    /// <summary>
    /// 
    /// </summary>
    ClientCertificate    = 8
}
