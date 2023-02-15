using System.Collections.Generic;

namespace SysadminsLV.PKI.Cryptography {
    /// <summary>
    /// Represents a collection of <see cref="CspProviderAlgorithmInfo"/> objects.
    /// </summary>
    public class CspProviderAlgorithmInfoCollection : BasicCollection<CspProviderAlgorithmInfo> {
        /// <inheritdoc />
        public CspProviderAlgorithmInfoCollection() { }
        /// <inheritdoc />
        public CspProviderAlgorithmInfoCollection(IEnumerable<CspProviderAlgorithmInfo> collection) : base(collection) { }
    }
}
