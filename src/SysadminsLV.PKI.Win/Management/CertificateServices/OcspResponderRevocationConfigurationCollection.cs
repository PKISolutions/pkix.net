using System;
using System.Collections.Generic;
using System.Linq;

namespace SysadminsLV.PKI.Management.CertificateServices {
    /// <summary>
    /// Represents a collection of Online Responder revocation configurations.
    /// </summary>
    public class OcspResponderRevocationConfigurationCollection : BasicCollection<OcspResponderRevocationConfiguration> {
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection() { }
        /// <inheritdoc />
        public OcspResponderRevocationConfigurationCollection(IEnumerable<OcspResponderRevocationConfiguration> collection) : base(collection) { }

        /// <summary>
        /// Gets Online Responder revocation configuration by name. If named configuration is not found, the indexer returns null.
        /// </summary>
        /// <param name="name">Revocation configuration name.</param>
        public OcspResponderRevocationConfiguration this[String name] => InternalList.FirstOrDefault(x => x.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase));
    }
}
