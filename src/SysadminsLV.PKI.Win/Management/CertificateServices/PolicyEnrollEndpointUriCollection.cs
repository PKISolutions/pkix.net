using System;
using System.Collections.Generic;
using System.Linq;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a collection of enrollment web service (CES) URL collection.
    /// </summary>
    public class PolicyEnrollEndpointUriCollection : BasicCollection<PolicyEnrollEndpointUri> {
        /// <inheritdoc />
        public PolicyEnrollEndpointUriCollection() { }
        /// <inheritdoc />
        public PolicyEnrollEndpointUriCollection(IEnumerable<PolicyEnrollEndpointUri> collection) : base(collection) { }

        /// <summary>
        /// Encodes a collection of enrollment web service URLs to an Active Directory compatible format.
        /// </summary>
        /// <returns>Encoded and formatted string.</returns>
        public String DsEncode() {
            return this.Any()
                ? String.Join("\n\n", this.Select(x => x.Encode()))
                : null;
        }
    }
}