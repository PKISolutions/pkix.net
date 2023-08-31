using System;

namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Represents the Online Responder audit filter options that are logged in Security event log.
/// <para>This enumeration has a <see cref="FlagsAttribute"/> attribute that allows a bitwise combination of its member values.</para>
/// </summary>
[Flags]
public enum OcspResponderAuditFilter {
    /// <summary>
    /// Nothing is audited.
    /// </summary>
    None                = 0,
    /// <summary>
    /// Audit start/stop of the service.
    /// </summary>
    StartAndStop        = 1,
    /// <summary>
    /// Audit changes to the revocation configurations on the responder.
    /// </summary>
    ConfigurationChange = 2,
    /// <summary>
    /// Audit OCSP requests received by the responder.
    /// </summary>
    RequestReceive      = 4,
    /// <summary>
    /// Audit changes to the security descriptor on the responder.
    /// </summary>
    SecurityChange      = 8
}