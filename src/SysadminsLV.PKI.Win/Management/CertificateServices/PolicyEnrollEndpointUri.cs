using System;
using SysadminsLV.PKI.Dcom;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents Certificate Enrollment Web Services (CES) URL object.
    /// </summary>
    public class PolicyEnrollEndpointUri {
        /// <summary>
        /// Initializes a new instance of <strong>PolicyEnrollEndpointUri</strong> from a string URI and remote endpoint settings.
        /// </summary>
        /// <param name="uri">Specifies an URI that points to Certificate Enrollment server.</param>
        /// <param name="authentication">Specifies the authentication type associated with specified enrollment server endpoint.</param>
        /// <param name="priority">Specifies the priority of the specified enrollment server endpoint.</param>
        /// <param name="renewalOnly">Indicates whether the specified enrollment supports only renewal requests. Default value is <strong>False</strong>.</param>
        /// <param name="keyBasedRenewal">Indicates whether the key-based renewal is supported by this enrollment endpoint. Default value is <strong>False</strong>.</param>
        public PolicyEnrollEndpointUri(String uri, PolicyEnrollAuthenticationType authentication, Int32 priority, Boolean renewalOnly = false, Boolean keyBasedRenewal = false) {
            if (String.IsNullOrEmpty(uri)) {
                throw new ArgumentNullException(nameof(uri));
            }

            Uri = new Uri(uri);
            Authentication = authentication;
            Priority = priority;
            RenewalOnly = renewalOnly;
            KeyBasedRenewal = keyBasedRenewal;
        }
        internal PolicyEnrollEndpointUri(ICertConfigEnrollEndpointD dcomUri) {
            Uri = new Uri(dcomUri.Uri);
            Authentication = (PolicyEnrollAuthenticationType)dcomUri.Authentication;
            Priority = dcomUri.Priority;
            RenewalOnly = dcomUri.RenewalOnly;
            KeyBasedRenewal = dcomUri.KeyBasedRenewal;
        }

        /// <summary>
        /// Gets enrollment web services endpoint URL.
        /// </summary>
        public Uri Uri { get; }
        /// <summary>
        /// Gets the authentication type.
        /// </summary>
        public PolicyEnrollAuthenticationType Authentication { get; }
        /// <summary>
        /// Gets the priority of this endpoint.
        /// </summary>
        public Int32 Priority { get; }
        /// <summary>
        /// Indicates whether the endpoint is for renewal requests only (<strong>True</strong>), or accepts initial requests (<strong>False</strong>).
        /// </summary>
        public Boolean RenewalOnly { get; }
        /// <summary>
        /// Indicates whether the endpoint supports key-based renewal.
        /// </summary>
        public Boolean KeyBasedRenewal { get; }

        /// <summary>
        /// Encodes a collection of enrollment web service URLs to an Active Directory compatible format.
        /// </summary>
        /// <returns>Encoded and formatted string.</returns>
        public String Encode() {
            return $"{Priority}\n{Convert.ToInt32(Authentication)}\n{Convert.ToInt32(RenewalOnly)}\n{Uri.AbsoluteUri}\n{Convert.ToInt32(KeyBasedRenewal)}";
        }

        /// <inheritdoc />
        public override String ToString() {
            return Uri.AbsoluteUri;
        }
    }
}