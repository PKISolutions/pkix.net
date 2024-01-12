using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices;
/// <summary>
/// Represents a collection of AD CS Certification Authority (CA) Authority Information Access (AIA) URL collection.
/// </summary>
public class CertSrvAiaUrlCollection : BasicCollection<CertSrvAiaUrlEntry> {
    /// <inheritdoc/>
    public CertSrvAiaUrlCollection() { }
    /// <inheritdoc/>
    public CertSrvAiaUrlCollection(IEnumerable<CertSrvAiaUrlEntry> collection) : base(collection) { }
}