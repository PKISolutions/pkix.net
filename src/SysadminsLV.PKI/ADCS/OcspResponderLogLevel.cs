namespace SysadminsLV.PKI.ADCS;

/// <summary>
/// Defines the level of information that is to be communicated to the system (application eventlog channel) as part
/// of operations being performed on the service.
/// </summary>
public enum OcspResponderLogLevel {
    /// <summary>
    /// Log events for errors and warnings that occur on the responder.
    /// </summary>
    Minimal    = 0,
    /// <summary>
    /// Log errors, warnings, and informational events.
    /// </summary>
    Terse      = 3,
    /// <summary>
    /// Log extended events.
    /// </summary>
    Verbose    = 4,
    /// <summary>
    /// Throttling is removed for events that can be generated quickly, such as MSG_E_POSSIBLE_DENIAL_OF_SERVICE_ATTACK.
    /// </summary>
    Exhaustive = 6
}