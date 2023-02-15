using System;

namespace SysadminsLV.PKI.Dcom {
    /// <summary>
    /// Represents an <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea">[MS-WSTEP]</see>
    /// ADCS Enrollment Web Services enrollment endpoint.
    /// </summary>
    public interface ICertConfigEnrollEndpointD {
        /// <summary>
        /// Gets enrollment web services endpoint URL.
        /// </summary>
        String Uri { get; }
        /// <summary>
        /// Gets the authentication type.
        /// </summary>
        AdcsEnrollAuthenticationType Authentication { get; }
        /// <summary>
        /// Gets the priority of this endpoint.
        /// </summary>
        Int32 Priority { get; }
        /// <summary>
        /// Indicates whether the endpoint is for renewal requests only (<strong>True</strong>), or accepts initial requests (<strong>False</strong>).
        /// </summary>
        Boolean RenewalOnly { get; }
        /// <summary>
        /// Indicates whether the endpoint supports key-based renewal.
        /// </summary>
        Boolean KeyBasedRenewal { get; }

        /// <summary>
        /// Encodes a enrollment web service URL to an Active Directory compatible format.
        /// </summary>
        /// <returns>Encoded and formatted string.</returns>
        String DsEncode();
    }
}