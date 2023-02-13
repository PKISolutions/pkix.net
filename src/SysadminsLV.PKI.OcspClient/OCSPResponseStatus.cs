namespace SysadminsLV.PKI.OcspClient;

/// <summary>
/// Contains possible OCSP response statuses.
/// </summary>
public enum OCSPResponseStatus {
    /// <summary>
    /// Response has valid confirmations.
    /// </summary>
    Successful = 0,
    /// <summary>
    /// A server produces the "malformedRequest" response if the request received does not conform to the OCSP syntax.
    /// </summary>
    MalformedRequest = 1,
    /// <summary>
    /// The response "internalError" indicates that the OCSP responder reached an inconsistent internal state.
    /// The query should be retried, potentially with another responder.
    /// </summary>
    InternalError = 2,
    /// <summary>
    /// In the event that the OCSP responder is operational, but unable to return a status for the requested certificate,
    /// the "tryLater" response can be used to indicate that the service exists, but is temporarily unable to respond.
    /// </summary>
    TryLater = 3,
    //4 not used
    /// <summary>
    /// The response "sigRequired" is returned in cases where the server requires the client sign the request in order
    /// to construct a response.
    /// </summary>
    SignatureRequired = 5,
    /// <summary>
    /// The response "unauthorized" is returned in cases where the client is not authorized to make this query to this server.
    /// </summary>
    Unauthorized = 6
}