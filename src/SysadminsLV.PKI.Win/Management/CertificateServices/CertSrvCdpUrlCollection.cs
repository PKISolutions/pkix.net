using System.Collections.Generic;

namespace SysadminsLV.PKI.Management.CertificateServices;

/// <summary>
/// Represents a collection of AD CS Certification Authority (CA) CRL Distribution Point (CDP) URL collection.
/// </summary>
public class CertSrvCdpUrlCollection : BasicCollection<CertSrvCdpUrlEntry> {
    /// <inheritdoc/>
    public CertSrvCdpUrlCollection() { }
    /// <inheritdoc/>
    public CertSrvCdpUrlCollection(IEnumerable<CertSrvCdpUrlEntry> collection) : base(collection) { }
}