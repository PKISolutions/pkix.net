using System.Collections.Generic;

namespace SysadminsLV.PKI.Cryptography.X509Certificates;

/// <summary>
/// Represents a collection of <see cref="SysadminsLV.PKI.Cryptography.X509Certificates.OidMapping"/> objects.
/// </summary>
public class OidMappingCollection : BasicCollection<OidMapping> {
    /// <inheritdoc />
    public OidMappingCollection() { }
    /// <inheritdoc />
    public OidMappingCollection(IEnumerable<OidMapping> collection) : base(collection) { }
    
}