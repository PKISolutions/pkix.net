namespace SysadminsLV.PKI.OcspClient;

/// <summary>
/// Contains possible OCSP response types. Currently only <strong>id_pkix_ocsp_basic</strong> type is supported.
/// </summary>
public enum OCSPResponseType {
    /// <summary>
    /// A response is Basic OCSP Response.
    /// </summary>
    id_pkix_ocsp_basic,
    /// <summary>
    /// A response is Full OCSP Response.
    /// </summary>
    /// <para><strong>Note:</strong> currently is not implemented and is never used.</para>
    id_pkix_ocsp_response,
}